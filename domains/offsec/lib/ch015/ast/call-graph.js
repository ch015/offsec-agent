'use strict';

const path = require('path');

// Framework route registration patterns — structural fact, not security judgment
const ROUTE_PATTERNS = [
  /^(app|router)\.(get|post|put|patch|delete|all|use)$/,
  /\.(get|post|put|patch|delete|all|use)$/,
  /^router\.(Get|Post|Put|Patch|Delete|Handle|HandleFunc)$/,
];

function extractCallGraph(parsedFiles, basePath) {
  const graph = {
    nodes: new Map(),
    edges: [],
    entryPoints: [],
    imports: new Map(),
    assignments: [],
  };

  for (const parsed of parsedFiles) {
    const relPath = path.relative(basePath, parsed.filePath);
    const extractor = getExtractor(parsed.language);
    if (!extractor) continue;

    const fileResult = extractor(parsed.tree.rootNode, parsed.source, relPath);

    for (const fn of fileResult.functions) {
      const key = `${relPath}:${fn.name}`;
      graph.nodes.set(key, { ...fn, file: relPath });
    }

    for (const call of fileResult.calls) {
      graph.edges.push({ ...call, file: relPath });
    }

    for (const ep of fileResult.entryPoints) {
      graph.entryPoints.push({ ...ep, file: relPath });
    }

    for (const imp of fileResult.imports) {
      const key = relPath;
      if (!graph.imports.has(key)) graph.imports.set(key, []);
      graph.imports.get(key).push(imp);
    }

    for (const a of fileResult.assignments || []) {
      graph.assignments.push({ ...a, file: relPath });
    }
  }

  resolveImportEdges(graph);
  return serializeGraph(graph);
}

function getExtractor(language) {
  switch (language) {
    case 'javascript':
    case 'typescript':
    case 'tsx':
      return extractJS;
    case 'python':
      return extractPython;
    case 'go':
      return extractGo;
    case 'java':
      return extractJava;
    case 'rust':
      return extractRust;
    case 'c':
    case 'cpp':
      return extractC;
    case 'kotlin':
      return extractKotlin;
    case 'swift':
      return extractSwift;
    case 'objc':
      return extractObjC;
    case 'c_sharp':
      return extractCSharp;
    case 'ruby':
      return extractRuby;
    case 'php':
      return extractPHP;
    case 'dart':
      return extractDart;
    case 'solidity':
      return extractSolidity;
    case 'elixir':
      return extractElixir;
    case 'hcl':
      return extractHCL;
    default:
      return null;
  }
}

// 대입 LHS에서 바인딩 식별자들을 수집한다. 단순 식별자 + 구조분해(JS object/array
// pattern, Python tuple/list pattern)를 모두 처리해 `const { file } = req.body`의 file도
// taint로 기록되게 한다. pair_pattern은 키가 아닌 바인딩(value) 쪽만 취한다.
function collectPatternBindings(node, source, out) {
  if (!node) return;
  const t = node.type;
  if (t === 'identifier' || t === 'shorthand_property_identifier_pattern') {
    out.push(getText(node, source));
    return;
  }
  if (t === 'pair_pattern') {
    const val = node.childForFieldName('value') || node.namedChildren[node.namedChildren.length - 1];
    collectPatternBindings(val, source, out);
    return;
  }
  if (t === 'rest_pattern' || t === 'assignment_pattern' || t === 'list_splat_pattern') {
    for (const c of node.namedChildren) collectPatternBindings(c, source, out);
    return;
  }
  if (t === 'object_pattern' || t === 'array_pattern' || t === 'tuple_pattern' ||
      t === 'list_pattern' || t === 'pattern_list') {
    for (const c of node.namedChildren) collectPatternBindings(c, source, out);
    return;
  }
}

// nameNode(단순 또는 구조분해) × valueNode(RHS)를 assignments로 펼친다. 구조분해는 각
// 바인딩이 동일 RHS를 상속한다 (const {a,b} = src → a,b 모두 src에서 파생).
function pushSourceAssignments(nameNode, valueNode, source, line, assignments) {
  if (!nameNode || !valueNode) return;
  const vExpr = getText(valueNode, source);
  if (!vExpr) return;
  const names = [];
  if (nameNode.type === 'identifier') names.push(getText(nameNode, source));
  else collectPatternBindings(nameNode, source, names);
  for (const nm of names) {
    if (nm && /^[A-Za-z_$][\w$]*$/.test(nm)) {
      assignments.push({ name: nm, expr: vExpr, line });
    }
  }
}

// ─── JavaScript / TypeScript extractor ───

function extractJS(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];
  const assignments = [];

  walkNode(rootNode, (node) => {
    if (isFunctionNode(node)) {
      const name = getFunctionName(node, source);
      if (name) {
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: node.type,
          params: extractParams(node, source),
        });

        // NestJS decorators: @Get(), @Post(), @Put(), @Delete(), @Patch()
        const decorators = getDecorators(node, source);
        for (const dec of decorators) {
          const nestMatch = dec.match(/@(Get|Post|Put|Delete|Patch|All)\s*\(\s*(['"`]([^'"`]*)['"`])?\s*\)/);
          if (nestMatch) {
            entryPoints.push({
              type: 'http',
              method: nestMatch[1].toLowerCase(),
              line: node.startPosition.row + 1,
              handler: name,
              route: nestMatch[3] || null,
            });
          }

          // GraphQL resolvers (Apollo/type-graphql/NestJS): @Query/@Mutation/@Subscription/@ResolveField
          const gqlMatch = dec.match(/@(Query|Mutation|Subscription|ResolveField)\s*\(/);
          if (gqlMatch) {
            entryPoints.push({
              type: 'graphql',
              method: gqlMatch[1].toLowerCase(),
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }

        // Lambda/Serverless handler: exports.handler or module.exports.handler
        if (name === 'handler' || name === 'main') {
          const parent = node.parent;
          if (parent?.type === 'assignment_expression') {
            const left = getText(parent.childForFieldName('left') || parent.namedChildren[0], source);
            if (left.match(/^(module\.)?exports\.(handler|main)$/) || left === 'module.exports') {
              entryPoints.push({
                type: 'serverless',
                method: 'handler',
                line: node.startPosition.row + 1,
                handler: name,
                route: null,
              });
            }
          }
        }
      }
    }

    if (node.type === 'call_expression') {
      const callee = getCallTarget(node, source);
      if (callee) {
        const argNodes = getCallArguments(node, source);
        calls.push({
          callee,
          line: node.startPosition.row + 1,
          arguments: argNodes,
        });

        if (isRouteRegistration(callee)) {
          entryPoints.push({
            type: 'http',
            method: extractHttpMethod(callee),
            line: node.startPosition.row + 1,
            handler: extractHandlerName(node, source),
            route: extractRouteString(node, source),
          });
        }

        // WebSocket handlers: io.on('connection'), socket.on('message'), ws.on('message').
        // Precision guard: only the ws-ish receivers, or a generic `.on` whose event is a
        // connection/message/upgrade lifecycle event — avoids flagging every EventEmitter.
        {
          const isWsReceiver = /^(io|socket|ws|wss)\.on$/.test(callee);
          const firstArg = String((argNodes[0] && (argNodes[0].expr ?? argNodes[0])) || '').replace(/['"`]/g, '');
          const isWsEvent = callee.endsWith('.on') && ['connection', 'message', 'upgrade'].includes(firstArg);
          if (isWsReceiver || isWsEvent) {
            entryPoints.push({
              type: 'websocket',
              method: 'ws_event',
              line: node.startPosition.row + 1,
              handler: extractHandlerName(node, source),
              route: firstArg || null,
            });
          }
        }

        // Bull/BullMQ worker: new Worker('name', processor) or queue.process(handler)
        if (callee === 'queue.process' || callee.endsWith('.process')) {
          entryPoints.push({
            type: 'worker',
            method: 'queue_process',
            line: node.startPosition.row + 1,
            handler: extractHandlerName(node, source),
            route: null,
          });
        }
      }
    }

    // new Worker(...) for BullMQ
    if (node.type === 'new_expression') {
      const ctorNode = node.childForFieldName('constructor') || node.namedChildren[0];
      if (ctorNode && getText(ctorNode, source) === 'Worker') {
        entryPoints.push({
          type: 'worker',
          method: 'bullmq_worker',
          line: node.startPosition.row + 1,
          handler: null,
          route: null,
        });
      }
    }

    // NestJS @Controller() class decorator
    if (node.type === 'decorator') {
      const decText = getText(node, source);
      const controllerMatch = decText.match(/@Controller\s*\(\s*(['"`]([^'"`]*)['"`])?\s*\)/);
      if (controllerMatch) {
        entryPoints.push({
          type: 'http_controller',
          method: 'controller',
          line: node.startPosition.row + 1,
          handler: null,
          route: controllerMatch[2] || null,
        });
      }
    }

    // Variable assignments — capture LHS name + RHS expression so taint can resolve
    // 변수 경유 흐름(const t = req.query.x; sink(t)). LHS가 단순 식별자일 때만.
    if (node.type === 'variable_declarator' || node.type === 'assignment_expression') {
      const nameNode = node.childForFieldName('name') || node.childForFieldName('left');
      const valueNode = node.childForFieldName('value') || node.childForFieldName('right');
      pushSourceAssignments(nameNode, valueNode, source, node.startPosition.row + 1, assignments);
    }

    if (node.type === 'import_statement' || node.type === 'call_expression') {
      const imp = extractImportJS(node, source);
      if (imp) imports.push(imp);
    }
  });

  // Next.js file-based API routes: pages/api/**/*.ts or app/**/route.ts
  if (filePath.match(/(?:pages\/api\/|app\/.*\/route\.)[jt]sx?$/)) {
    entryPoints.push({
      type: 'http',
      method: 'file_route',
      line: 1,
      handler: 'default_export',
      route: filePathToNextRoute(filePath),
    });
  }

  // Second pass: export statements for Next.js App Router, SDK surface, and Angular/React
  walkNode(rootNode, (node) => {
    if (node.type === 'export_statement') {
      const exported = getText(node, source);

      // Next.js App Router: export function GET/POST/...
      for (const method of ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']) {
        if (exported.includes(`function ${method}`) || exported.includes(`const ${method}`)) {
          entryPoints.push({
            type: 'http',
            method: method.toLowerCase(),
            line: node.startPosition.row + 1,
            handler: method,
            route: filePathToNextRoute(filePath),
          });
        }
      }

      // SDK: exported functions/classes as public API surface
      const exportedNameMatch = exported.match(/export\s+(?:default\s+)?(?:function|class|const|let|var)\s+(\w+)/);
      if (exportedNameMatch) {
        entryPoints.push({
          type: 'sdk_export',
          method: 'export',
          line: node.startPosition.row + 1,
          handler: exportedNameMatch[1],
          route: null,
        });
      }
    }

    // Angular: @Component decorator with template/selector
    if (node.type === 'decorator') {
      const decText = getText(node, source);
      const componentMatch = decText.match(/@Component\s*\(/);
      if (componentMatch) {
        const selectorMatch = decText.match(/selector\s*:\s*['"`]([^'"`]+)['"`]/);
        entryPoints.push({
          type: 'angular_component',
          method: 'component',
          line: node.startPosition.row + 1,
          handler: selectorMatch?.[1] || null,
          route: null,
        });
      }
    }

    // React Router: <Route path="..." />, createBrowserRouter([...])
    if (node.type === 'call_expression') {
      const callee = getCallTarget(node, source);
      if (callee === 'createBrowserRouter' || callee === 'createHashRouter' || callee === 'createMemoryRouter') {
        entryPoints.push({
          type: 'react_router',
          method: 'router',
          line: node.startPosition.row + 1,
          handler: callee,
          route: null,
        });
      }
    }

    // JSX Route element: <Route path="/..." />
    if (node.type === 'jsx_self_closing_element' || node.type === 'jsx_opening_element') {
      const tagName = node.namedChildren[0];
      if (tagName && getText(tagName, source) === 'Route') {
        const pathAttr = node.namedChildren.find(c => {
          if (c.type !== 'jsx_attribute') return false;
          const attrName = c.namedChildren[0];
          return attrName && getText(attrName, source) === 'path';
        });
        const pathValue = pathAttr?.namedChildren[1];
        const route = pathValue ? getText(pathValue, source).replace(/['"{}]/g, '') : null;
        entryPoints.push({
          type: 'react_route',
          method: 'route',
          line: node.startPosition.row + 1,
          handler: null,
          route,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports, assignments };
}

function filePathToNextRoute(filePath) {
  let route = filePath
    .replace(/^.*pages\/api\//, '/api/')
    .replace(/^.*app\//, '/')
    .replace(/\/route\.[jt]sx?$/, '')
    .replace(/\/index\.[jt]sx?$/, '')
    .replace(/\.[jt]sx?$/, '')
    .replace(/\[([^\]]+)\]/g, ':$1');
  return route || '/';
}

// ─── Python extractor ───

function extractPython(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];
  const assignments = [];

  walkNode(rootNode, (node) => {
    // 변수 대입 캡처: cmd = request.json['command'] → taint가 변수 경유를 해석.
    if (node.type === 'assignment') {
      const nameNode = node.childForFieldName('left');
      const valueNode = node.childForFieldName('right');
      pushSourceAssignments(nameNode, valueNode, source, node.startPosition.row + 1, assignments);
    }

    if (node.type === 'function_definition') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'function',
          params: extractPythonParams(node, source),
        });

        const decorators = getDecorators(node, source);
        for (const dec of decorators) {
          // Flask/FastAPI: @app.get('/path'), @router.post('/path')
          if (dec.match(/@(app|router)\.(get|post|put|patch|delete|route)/)) {
            entryPoints.push({
              type: 'http',
              method: dec.match(/\.(get|post|put|patch|delete|route)/)?.[1] || 'unknown',
              line: node.startPosition.row + 1,
              handler: name,
              route: dec.match(/['"](\/[^'"]*)['"]/)?.[1] || null,
            });
          }

          // Celery: @celery.task, @shared_task, @app.task
          if (dec.match(/@(celery\.task|shared_task|app\.task)/)) {
            entryPoints.push({
              type: 'worker',
              method: 'celery_task',
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }

        // Lambda handler: def handler(event, context) or def lambda_handler(event, context)
        if (name.match(/^(handler|lambda_handler|main)$/)) {
          const params = extractPythonParams(node, source);
          if (params.some(p => p.includes('event'))) {
            entryPoints.push({
              type: 'serverless',
              method: 'handler',
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }
      }
    }

    if (node.type === 'call') {
      const funcNode = node.childForFieldName('function');
      if (funcNode) {
        const callee = getText(funcNode, source);
        const argNodes = getPythonCallArguments(node, source);
        calls.push({ callee, line: node.startPosition.row + 1, arguments: argNodes });

        // Django: path('route/', view_func) or re_path(r'pattern', view_func)
        if (callee === 'path' || callee === 're_path') {
          const routeArg = argNodes[0]?.expr?.replace(/['"]/g, '') || null;
          const handlerArg = argNodes[1]?.expr || null;
          entryPoints.push({
            type: 'http',
            method: 'django_url',
            line: node.startPosition.row + 1,
            handler: handlerArg,
            route: routeArg ? `/${routeArg}` : null,
          });
        }
      }
    }

    if (node.type === 'import_statement' || node.type === 'import_from_statement') {
      imports.push({
        module: getText(node, source).replace(/^(from\s+|import\s+)/, '').split(/\s+import\s+/)[0],
        line: node.startPosition.row + 1,
      });
    }
  });

  return { functions, calls, entryPoints, imports, assignments };
}

// ─── Go extractor ───

function extractGo(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'function_declaration' || node.type === 'method_declaration') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: node.type === 'method_declaration' ? 'method' : 'function',
        });
      }
    }

    if (node.type === 'call_expression') {
      const funcNode = node.childForFieldName('function');
      if (funcNode) {
        const callee = getText(funcNode, source);
        calls.push({ callee, line: node.startPosition.row + 1 });

        if (callee.match(/\.(HandleFunc|Handle|Get|Post|Put|Delete)\b/)) {
          entryPoints.push({
            type: 'http',
            method: callee.match(/\.(Get|Post|Put|Delete|HandleFunc|Handle)/)?.[1] || 'unknown',
            line: node.startPosition.row + 1,
          });
        }
      }
    }

    if (node.type === 'import_spec') {
      const pathNode = node.childForFieldName('path');
      if (pathNode) {
        imports.push({
          module: getText(pathNode, source).replace(/"/g, ''),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

// ─── Java extractor ───

function extractJava(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'method_declaration') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'method',
          params: extractJavaParams(node, source),
        });

        const annotations = getJavaAnnotations(node, source);
        for (const ann of annotations) {
          // Spring MVC: @GetMapping, @PostMapping, etc.
          const routeMatch = ann.match(/@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*(?:value\s*=\s*)?)?["']?([^"')]*)/);
          if (routeMatch) {
            const methodMap = {
              GetMapping: 'get', PostMapping: 'post', PutMapping: 'put',
              DeleteMapping: 'delete', PatchMapping: 'patch', RequestMapping: 'unknown',
            };
            entryPoints.push({
              type: 'http',
              method: methodMap[routeMatch[1]] || 'unknown',
              line: node.startPosition.row + 1,
              handler: name,
              route: routeMatch[2] || null,
            });
          }

          // Spring @Scheduled
          if (ann.match(/@Scheduled/)) {
            entryPoints.push({
              type: 'scheduled',
              method: 'cron',
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }

        // Android lifecycle: onCreate, onStart, onResume, onCreateView
        if (name.match(/^(onCreate|onStart|onResume|onPause|onStop|onDestroy|onCreateView|onViewCreated|onReceive|onBind|onStartCommand)$/)) {
          entryPoints.push({
            type: 'android_lifecycle',
            method: name,
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }
      }
    }

    // Android class: extends Activity, AppCompatActivity, Fragment, Service, BroadcastReceiver
    if (node.type === 'class_declaration') {
      const superclass = node.childForFieldName('superclass');
      if (superclass) {
        const superName = getText(superclass, source);
        if (superName.match(/(Activity|AppCompatActivity|Fragment|Service|BroadcastReceiver|ContentProvider|ViewModel)\b/)) {
          const nameNode = node.childForFieldName('name');
          entryPoints.push({
            type: 'android_component',
            method: superName.replace(/.*\./, ''),
            line: node.startPosition.row + 1,
            handler: nameNode ? getText(nameNode, source) : null,
            route: null,
          });
        }
      }
    }

    if (node.type === 'method_invocation') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const objectNode = node.childForFieldName('object');
        const name = getText(nameNode, source);
        const callee = objectNode ? `${getText(objectNode, source)}.${name}` : name;
        const argNodes = getGenericCallArguments(node, source);
        calls.push({ callee, line: node.startPosition.row + 1, arguments: argNodes });
      }
    }

    if (node.type === 'import_declaration') {
      const pathText = getText(node, source)
        .replace(/^import\s+(static\s+)?/, '')
        .replace(/;\s*$/, '')
        .trim();
      imports.push({ module: pathText, line: node.startPosition.row + 1 });
    }
  });

  return { functions, calls, entryPoints, imports };
}

function extractJavaParams(node, source) {
  const params = node.childForFieldName('parameters');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'formal_parameter' || p.type === 'spread_parameter')
    .map(p => {
      const nameNode = p.childForFieldName('name');
      return nameNode ? getText(nameNode, source) : getText(p, source);
    })
    .filter(Boolean);
}

function getJavaAnnotations(node, source) {
  const annotations = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child.type === 'modifiers') {
      for (let j = 0; j < child.namedChildCount; j++) {
        const mod = child.namedChild(j);
        if (mod.type === 'marker_annotation' || mod.type === 'annotation') {
          annotations.push(getText(mod, source));
        }
      }
    }
    if (child.type === 'marker_annotation' || child.type === 'annotation') {
      annotations.push(getText(child, source));
    }
  }
  return annotations;
}

// ─── Rust extractor ───

function extractRust(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'function_item') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'function',
          params: extractRustParams(node, source),
        });

        const attrs = getRustAttributes(node, source);
        for (const attr of attrs) {
          // Actix-Web / Rocket: #[get("/path")], #[actix_web::get("/path")]
          const routeMatch = attr.match(/#\[(?:actix_web::|rocket::)?(get|post|put|delete|patch)\s*\(\s*"([^"]*)"/i);
          if (routeMatch) {
            entryPoints.push({
              type: 'http',
              method: routeMatch[1].toLowerCase(),
              line: node.startPosition.row + 1,
              handler: name,
              route: routeMatch[2],
            });
          }

          // Anchor (Solana): #[program], #[account]
          if (attr.match(/#\[program\]/)) {
            entryPoints.push({
              type: 'web3_program',
              method: 'anchor_program',
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }
      }
    }

    if (node.type === 'call_expression') {
      const funcNode = node.childForFieldName('function');
      if (funcNode) {
        const callee = getText(funcNode, source);
        const argNodes = getGenericCallArguments(node, source);
        calls.push({ callee, line: node.startPosition.row + 1, arguments: argNodes });

        // Axum: .route("/path", get(handler)) or Router::new().route(...)
        if (callee.match(/\.route$/) || callee === 'route') {
          const routeArg = argNodes[0]?.expr?.replace(/['"]/g, '') || null;
          entryPoints.push({
            type: 'http',
            method: 'axum_route',
            line: node.startPosition.row + 1,
            handler: argNodes[1]?.expr || null,
            route: routeArg,
          });
        }
      }
    }

    if (node.type === 'use_declaration') {
      const argNode = node.childForFieldName('argument') || node.namedChildren[0];
      if (argNode) {
        imports.push({
          module: getText(argNode, source),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

function extractRustParams(node, source) {
  const params = node.childForFieldName('parameters');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'parameter' || p.type === 'self_parameter')
    .map(p => {
      const pattern = p.childForFieldName('pattern');
      return pattern ? getText(pattern, source) : getText(p, source);
    })
    .filter(Boolean);
}

function getRustAttributes(node, source) {
  const attrs = [];
  let prev = node.previousNamedSibling;
  while (prev && prev.type === 'attribute_item') {
    attrs.push(getText(prev, source));
    prev = prev.previousNamedSibling;
  }
  return attrs;
}

// ─── C / C++ extractor ───

function extractC(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'function_definition') {
      const name = getCFunctionName(node, source);
      if (name) {
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'function',
        });
        if (name === 'main') {
          entryPoints.push({
            type: 'cli',
            method: 'main',
            line: node.startPosition.row + 1,
            handler: 'main',
          });
        }
      }
    }

    // Unreal Engine: UFUNCTION() macro before function declarations
    if (node.type === 'expression_statement') {
      const text = getText(node, source);
      if (text.match(/UFUNCTION\s*\(/)) {
        const next = node.nextNamedSibling;
        if (next && next.type === 'function_definition') {
          const ufName = getCFunctionName(next, source);
          entryPoints.push({
            type: 'unreal_ufunction',
            method: 'ufunction',
            line: node.startPosition.row + 1,
            handler: ufName || null,
            route: null,
          });
        }
      }
      if (text.match(/UCLASS\s*\(/)) {
        entryPoints.push({
          type: 'unreal_uclass',
          method: 'uclass',
          line: node.startPosition.row + 1,
          handler: null,
          route: null,
        });
      }
    }

    if (node.type === 'call_expression') {
      const funcNode = node.childForFieldName('function');
      if (funcNode) {
        const callee = getText(funcNode, source);
        const argNodes = getGenericCallArguments(node, source);
        calls.push({ callee, line: node.startPosition.row + 1, arguments: argNodes });
      }
    }

    if (node.type === 'preproc_include') {
      const pathNode = node.childForFieldName('path');
      if (pathNode) {
        imports.push({
          module: getText(pathNode, source).replace(/[<>"]/g, ''),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

function getCFunctionName(node, source) {
  let declarator = node.childForFieldName('declarator');
  if (!declarator) return null;
  while (declarator && declarator.type !== 'function_declarator' && declarator.type !== 'identifier') {
    declarator = declarator.childForFieldName('declarator') || declarator.namedChildren?.[0];
  }
  if (!declarator) return null;
  if (declarator.type === 'function_declarator') {
    const id = declarator.childForFieldName('declarator');
    return id ? getText(id, source) : null;
  }
  return getText(declarator, source);
}

// ─── Kotlin extractor ───

function extractKotlin(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'function_declaration') {
      const nameNode = node.childForFieldName('name')
        || node.namedChildren.find(c => c.type === 'simple_identifier');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'function',
          params: extractKotlinParams(node, source),
        });

        const annotations = getKotlinAnnotations(node, source);
        for (const ann of annotations) {
          // Spring MVC: @GetMapping, @PostMapping, etc.
          const routeMatch = ann.match(/@(GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping|RequestMapping)\s*(?:\(\s*(?:value\s*=\s*)?)?["']?([^"')]*)/);

          if (routeMatch) {
            const methodMap = {
              GetMapping: 'get', PostMapping: 'post', PutMapping: 'put',
              DeleteMapping: 'delete', PatchMapping: 'patch', RequestMapping: 'unknown',
            };
            entryPoints.push({
              type: 'http',
              method: methodMap[routeMatch[1]] || 'unknown',
              line: node.startPosition.row + 1,
              handler: name,
              route: routeMatch[2] || null,
            });
          }

          // Spring @Scheduled
          if (ann.match(/@Scheduled/)) {
            entryPoints.push({
              type: 'scheduled',
              method: 'cron',
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }

          // Jetpack Compose: @Composable
          if (ann.match(/@Composable/)) {
            entryPoints.push({
              type: 'android_composable',
              method: 'composable',
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }

        // Android lifecycle methods
        if (name.match(/^(onCreate|onStart|onResume|onPause|onStop|onDestroy|onCreateView|onViewCreated|onReceive|onBind|onStartCommand)$/)) {
          entryPoints.push({
            type: 'android_lifecycle',
            method: name,
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }
      }
    }

    // Kotlin class: extends Activity, Fragment, etc.
    if (node.type === 'class_declaration') {
      const delegation = node.namedChildren.find(c => c.type === 'delegation_specifier');
      if (delegation) {
        const superName = getText(delegation, source);
        if (superName.match(/(Activity|AppCompatActivity|Fragment|Service|BroadcastReceiver|ContentProvider|ViewModel)\b/)) {
          const nameNode = node.childForFieldName('name')
            || node.namedChildren.find(c => c.type === 'simple_identifier');
          entryPoints.push({
            type: 'android_component',
            method: superName.replace(/.*[\.(]/, '').replace(/\).*/, ''),
            line: node.startPosition.row + 1,
            handler: nameNode ? getText(nameNode, source) : null,
            route: null,
          });
        }
      }
    }

    if (node.type === 'call_expression') {
      const funcNode = node.namedChildren.find(c =>
        c.type === 'simple_identifier' || c.type === 'navigation_expression'
      );
      if (funcNode) {
        const callee = getText(funcNode, source);
        const argNodes = getGenericCallArguments(node, source);
        calls.push({ callee, line: node.startPosition.row + 1, arguments: argNodes });
      }
    }

    if (node.type === 'import_header') {
      const identifier = node.namedChildren.find(c => c.type === 'identifier');
      if (identifier) {
        imports.push({
          module: getText(identifier, source),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

function extractKotlinParams(node, source) {
  const params = node.childForFieldName('parameters')
    || node.namedChildren.find(c => c.type === 'function_value_parameters');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'parameter')
    .map(p => {
      const nameNode = p.childForFieldName('name')
        || p.namedChildren.find(c => c.type === 'simple_identifier');
      return nameNode ? getText(nameNode, source) : getText(p, source);
    })
    .filter(Boolean);
}

function getKotlinAnnotations(node, source) {
  const annotations = [];
  let prev = node.previousNamedSibling;
  while (prev && (prev.type === 'annotation' || prev.type === 'single_annotation')) {
    annotations.push(getText(prev, source));
    prev = prev.previousNamedSibling;
  }
  const modifiers = node.childForFieldName('modifiers');
  if (modifiers) {
    walkNode(modifiers, (child) => {
      if (child.type === 'annotation' || child.type === 'single_annotation') {
        annotations.push(getText(child, source));
      }
    });
  }
  return annotations;
}

// ─── Swift extractor ───

function extractSwift(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'function_declaration') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'function',
          params: extractSwiftParams(node, source),
        });

        // iOS lifecycle: viewDidLoad, viewWillAppear, etc.
        if (name.match(/^(viewDidLoad|viewWillAppear|viewDidAppear|viewWillDisappear|viewDidDisappear|applicationDidFinishLaunching|application|didReceiveRemoteNotification|userContentController)$/)) {
          entryPoints.push({
            type: 'ios_lifecycle',
            method: name,
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }

        // @IBAction
        const attrs = getSwiftAttributes(node, source);
        for (const attr of attrs) {
          if (attr.match(/@IBAction|@objc/)) {
            entryPoints.push({
              type: 'ios_action',
              method: 'ibaction',
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }
      }
    }

    // SwiftUI: struct ... : View
    if (node.type === 'class_declaration' || node.type === 'struct_declaration') {
      const nodeText = getText(node, source).slice(0, 200);
      if (nodeText.match(/:\s*(View|App)\b/)) {
        const nameNode = node.childForFieldName('name') || node.namedChildren.find(c => c.type === 'type_identifier' || c.type === 'simple_identifier');
        entryPoints.push({
          type: 'swiftui_view',
          method: 'view',
          line: node.startPosition.row + 1,
          handler: nameNode ? getText(nameNode, source) : null,
          route: null,
        });
      }
    }

    if (node.type === 'call_expression') {
      const funcNode = node.namedChildren[0];
      if (funcNode) {
        const callee = getText(funcNode, source);
        const argNodes = getGenericCallArguments(node, source);
        calls.push({ callee, line: node.startPosition.row + 1, arguments: argNodes });
      }
    }

    if (node.type === 'import_declaration') {
      const pathText = getText(node, source).replace(/^import\s+/, '').trim();
      imports.push({ module: pathText, line: node.startPosition.row + 1 });
    }
  });

  return { functions, calls, entryPoints, imports };
}

function getSwiftAttributes(node, source) {
  const attrs = [];
  let prev = node.previousNamedSibling;
  while (prev && (prev.type === 'attribute' || prev.type === 'modifiers')) {
    attrs.push(getText(prev, source));
    prev = prev.previousNamedSibling;
  }
  return attrs;
}

function extractSwiftParams(node, source) {
  const params = node.childForFieldName('parameters')
    || node.namedChildren.find(c => c.type === 'parameter_clause');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'parameter')
    .map(p => {
      const nameNode = p.childForFieldName('name') || p.childForFieldName('external_name');
      return nameNode ? getText(nameNode, source) : getText(p, source);
    })
    .filter(Boolean);
}

// ─── Objective-C / Objective-C++ extractor ───
// Handles .m (Obj-C) and .mm (Obj-C++). tree-sitter-objc tolerates the C++ subset in
// .mm with negligible error recovery (<1% ERROR nodes on real bridge files), so selector
// and message-send extraction stays accurate for native↔JS bridge auditing.

const OBJC_ENTRY_SELECTOR = /^(viewDidLoad|viewWillAppear|viewDidAppear|viewWillDisappear|viewDidDisappear|application|applicationDidFinishLaunching|didReceiveRemoteNotification|userContentController|load|initialize)\b/;

function extractObjC(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    // Obj-C method: - (ret)kw1:(T)a kw2:(T)b { ... }  → selector "kw1:kw2:"
    if (node.type === 'method_definition') {
      const selector = getObjCMethodSelector(node, source);
      if (selector) {
        const first = node.child(0);
        functions.push({
          name: selector,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: first && first.type === '+' ? 'class_method' : 'method',
          params: getObjCMethodParams(node, source),
        });
        if (OBJC_ENTRY_SELECTOR.test(selector)) {
          entryPoints.push({
            type: 'ios_lifecycle',
            method: selector.split(':')[0],
            line: node.startPosition.row + 1,
            handler: selector,
            route: null,
          });
        }
      }
    }

    // C-style function (common in .mm bridges): static int helper(int x) { ... }
    if (node.type === 'function_definition') {
      const name = getCFunctionName(node, source);
      if (name) {
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'function',
        });
      }
    }

    // Obj-C message send: [receiver kw1:arg kw2:arg]
    if (node.type === 'message_expression') {
      const callee = getObjCMessageSelector(node, source);
      if (callee) {
        const receiverNode = node.childForFieldName('receiver');
        calls.push({
          callee,
          line: node.startPosition.row + 1,
          receiver: receiverNode ? getText(receiverNode, source).slice(0, 60) : null,
        });
      }
    }

    // C-style call: doThing(x)
    if (node.type === 'call_expression') {
      const funcNode = node.childForFieldName('function');
      if (funcNode && funcNode.type === 'identifier') {
        calls.push({
          callee: getText(funcNode, source),
          line: node.startPosition.row + 1,
          arguments: getGenericCallArguments(node, source),
        });
      }
    }

    if (node.type === 'preproc_include') {
      const pathNode = node.childForFieldName('path');
      if (pathNode) {
        imports.push({
          module: getText(pathNode, source).replace(/[<>"]/g, ''),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

// Count direct-child ':' tokens — distinguishes keyword selectors from unary ones.
function countObjCColons(node) {
  let n = 0;
  for (let i = 0; i < node.childCount; i++) {
    if (node.child(i).type === ':') n++;
  }
  return n;
}

// method_definition: selector keywords are the direct `identifier` children
// (parameter names live nested inside `method_parameter`, so they are excluded).
function getObjCMethodSelector(node, source) {
  const labels = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c.type === 'identifier') labels.push(getText(c, source));
  }
  if (labels.length === 0) return null;
  const keyword = node.namedChildren.some(c => c.type === 'method_parameter');
  return keyword ? labels.join(':') + ':' : labels[0];
}

function getObjCMethodParams(node, source) {
  const params = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const c = node.namedChild(i);
    if (c.type === 'method_parameter') {
      const id = c.namedChildren.find(x => x.type === 'identifier');
      if (id) params.push(getText(id, source));
    }
  }
  return params;
}

// message_expression: selector keywords are the `method` field children.
function getObjCMessageSelector(node, source) {
  const labels = node.childrenForFieldName('method').map(m => getText(m, source));
  if (labels.length === 0) return null;
  return countObjCColons(node) > 0 ? labels.join(':') + ':' : labels[0];
}

// ─── C# extractor ───

function extractCSharp(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'method_declaration') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'method',
          params: extractCSharpParams(node, source),
        });

        const attrs = getCSharpAttributes(node, source);
        for (const attr of attrs) {
          // ASP.NET: [HttpGet], [HttpPost], etc.
          const routeMatch = attr.match(/\[(HttpGet|HttpPost|HttpPut|HttpDelete|HttpPatch|Route)\s*\(?\s*"?([^"\]]*)/);
          if (routeMatch) {
            const methodMap = {
              HttpGet: 'get', HttpPost: 'post', HttpPut: 'put',
              HttpDelete: 'delete', HttpPatch: 'patch', Route: 'unknown',
            };
            entryPoints.push({
              type: 'http',
              method: methodMap[routeMatch[1]] || 'unknown',
              line: node.startPosition.row + 1,
              handler: name,
              route: routeMatch[2] || null,
            });
          }

          // Unity Netcode: [ServerRpc], [ClientRpc]
          if (attr.match(/\[(ServerRpc|ClientRpc)/)) {
            entryPoints.push({
              type: 'unity_rpc',
              method: attr.includes('ServerRpc') ? 'server_rpc' : 'client_rpc',
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }

        // Unity lifecycle: Start, Update, Awake, OnEnable, OnCollisionEnter, etc.
        if (name.match(/^(Awake|Start|Update|FixedUpdate|LateUpdate|OnEnable|OnDisable|OnDestroy|OnCollisionEnter|OnCollisionExit|OnTriggerEnter|OnTriggerExit|OnApplicationPause|OnApplicationQuit)$/)) {
          entryPoints.push({
            type: 'unity_lifecycle',
            method: name,
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }
      }
    }

    // Unity: class ... : MonoBehaviour
    if (node.type === 'class_declaration') {
      const bases = node.childForFieldName('bases');
      if (bases) {
        const basesText = getText(bases, source);
        if (basesText.match(/(MonoBehaviour|NetworkBehaviour|ScriptableObject)\b/)) {
          const nameNode = node.childForFieldName('name');
          entryPoints.push({
            type: 'unity_component',
            method: basesText.match(/(MonoBehaviour|NetworkBehaviour|ScriptableObject)/)?.[1] || 'MonoBehaviour',
            line: node.startPosition.row + 1,
            handler: nameNode ? getText(nameNode, source) : null,
            route: null,
          });
        }
      }
    }

    if (node.type === 'invocation_expression') {
      const funcNode = node.childForFieldName('function') || node.namedChildren[0];
      if (funcNode) {
        const callee = getText(funcNode, source);
        const argNodes = getGenericCallArguments(node, source);
        calls.push({ callee, line: node.startPosition.row + 1, arguments: argNodes });
      }
    }

    if (node.type === 'using_directive') {
      const nameNode = node.childForFieldName('name')
        || node.namedChildren.find(c => c.type === 'qualified_name' || c.type === 'identifier_name');
      if (nameNode) {
        imports.push({
          module: getText(nameNode, source),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

function extractCSharpParams(node, source) {
  const params = node.childForFieldName('parameters');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'parameter')
    .map(p => {
      const nameNode = p.childForFieldName('name');
      return nameNode ? getText(nameNode, source) : getText(p, source);
    })
    .filter(Boolean);
}

function getCSharpAttributes(node, source) {
  const attrs = [];
  for (let i = 0; i < node.namedChildCount; i++) {
    const child = node.namedChild(i);
    if (child.type === 'attribute_list') {
      attrs.push(getText(child, source));
    }
  }
  let prev = node.previousNamedSibling;
  while (prev && prev.type === 'attribute_list') {
    attrs.push(getText(prev, source));
    prev = prev.previousNamedSibling;
  }
  return attrs;
}

// ─── Ruby extractor ───

function extractRuby(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'method') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'method',
          params: extractRubyParams(node, source),
        });

        // Rails controller actions: methods inside a class that ends with Controller
        if (isRailsControllerAction(node, source)) {
          entryPoints.push({
            type: 'http',
            method: 'rails_action',
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }

        // Sidekiq/ActiveJob: def perform(...)
        if (name === 'perform' && isInsideWorkerClass(node, source)) {
          entryPoints.push({
            type: 'worker',
            method: 'sidekiq_perform',
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }
      }
    }

    if (node.type === 'call') {
      const methodNode = node.childForFieldName('method');
      if (methodNode) {
        const receiverNode = node.childForFieldName('receiver');
        const method = getText(methodNode, source);
        const callee = receiverNode ? `${getText(receiverNode, source)}.${method}` : method;
        calls.push({ callee, line: node.startPosition.row + 1 });

        // Rails routes: get '/path', post '/path', resources :items, etc.
        if (['get', 'post', 'put', 'patch', 'delete', 'resources', 'resource', 'match'].includes(method)) {
          const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'argument_list');
          const routeArg = args?.namedChildren[0];
          const route = routeArg ? getText(routeArg, source).replace(/['":]/g, '').slice(0, 80) : null;
          entryPoints.push({
            type: method === 'resources' || method === 'resource' ? 'http_resource' : 'http',
            method: method === 'resources' || method === 'resource' ? 'restful' : method,
            line: node.startPosition.row + 1,
            handler: null,
            route,
          });
        }

        // Grape API: desc, get, post inside a class < Grape::API
        if (['desc'].includes(method) && isInsideGrapeAPI(node, source)) {
          const nextSibling = node.nextNamedSibling;
          if (nextSibling && nextSibling.type === 'call') {
            const nextMethod = nextSibling.childForFieldName('method');
            if (nextMethod && ['get', 'post', 'put', 'delete', 'patch'].includes(getText(nextMethod, source))) {
              entryPoints.push({
                type: 'http',
                method: getText(nextMethod, source),
                line: nextSibling.startPosition.row + 1,
                handler: null,
                route: null,
              });
            }
          }
        }
      }
    }

    // require/require_relative
    if (node.type === 'call') {
      const methodNode = node.childForFieldName('method');
      if (methodNode) {
        const method = getText(methodNode, source);
        if (method === 'require' || method === 'require_relative') {
          const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'argument_list');
          const firstArg = args?.namedChildren[0];
          if (firstArg) {
            imports.push({
              module: getText(firstArg, source).replace(/['"]/g, ''),
              line: node.startPosition.row + 1,
            });
          }
        }
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

function extractRubyParams(node, source) {
  const params = node.childForFieldName('parameters')
    || node.namedChildren.find(c => c.type === 'method_parameters');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'identifier' || p.type === 'optional_parameter' || p.type === 'keyword_parameter')
    .map(p => getText(p, source).replace(/:$/, ''))
    .filter(Boolean);
}

function isRailsControllerAction(methodNode, source) {
  let parent = methodNode.parent;
  while (parent) {
    if (parent.type === 'class' || parent.type === 'body_statement') {
      // Check if preceded by private/protected keyword
      let prev = methodNode.previousNamedSibling;
      while (prev) {
        if (prev.type === 'identifier') {
          const kw = getText(prev, source);
          if (kw === 'private' || kw === 'protected') return false;
        }
        if (prev.type === 'method') break;
        prev = prev.previousNamedSibling;
      }
    }
    if (parent.type === 'class') {
      const nameNode = parent.childForFieldName('name');
      if (nameNode && getText(nameNode, source).endsWith('Controller')) return true;
    }
    parent = parent.parent;
  }
  return false;
}

function isInsideWorkerClass(methodNode, source) {
  let parent = methodNode.parent;
  while (parent) {
    if (parent.type === 'class') {
      const superclass = parent.childForFieldName('superclass');
      if (superclass) {
        const text = getText(superclass, source);
        if (text.match(/(ApplicationJob|ActiveJob::Base|Sidekiq::Worker)/)) return true;
      }
      const body = getText(parent, source).slice(0, 300);
      if (body.match(/include\s+Sidekiq::Worker/)) return true;
    }
    parent = parent.parent;
  }
  return false;
}

function isInsideGrapeAPI(node, source) {
  let parent = node.parent;
  while (parent) {
    if (parent.type === 'class') {
      const superclass = parent.childForFieldName('superclass');
      if (superclass && getText(superclass, source).match(/Grape::API/)) return true;
    }
    parent = parent.parent;
  }
  return false;
}

// ─── PHP extractor ───

function extractPHP(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'function_definition' || node.type === 'method_declaration') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: node.type === 'method_declaration' ? 'method' : 'function',
          params: extractPHPParams(node, source),
        });

        // Laravel controller methods with Route:: annotations or PHPDoc @route
        if (isLaravelControllerMethod(node, source)) {
          entryPoints.push({
            type: 'http',
            method: 'laravel_action',
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }

        // Symfony: #[Route('/path')] attribute
        const phpAttrs = getPHPAttributes(node, source);
        for (const attr of phpAttrs) {
          const routeMatch = attr.match(/#\[Route\s*\(\s*['"]([^'"]*)['"]/);
          if (routeMatch) {
            const methodMatch = attr.match(/methods:\s*\[['"](\w+)['"]/);
            entryPoints.push({
              type: 'http',
              method: methodMatch ? methodMatch[1].toLowerCase() : 'unknown',
              line: node.startPosition.row + 1,
              handler: name,
              route: routeMatch[1],
            });
          }
        }
      }
    }

    if (node.type === 'function_call_expression' || node.type === 'member_call_expression' || node.type === 'scoped_call_expression') {
      const funcNode = node.childForFieldName('function') || node.childForFieldName('name');
      if (funcNode) {
        const callee = getText(funcNode, source);
        calls.push({ callee, line: node.startPosition.row + 1 });

        // Laravel Route:: facade: Route::get('/path', [Controller::class, 'method'])
        const fullCallee = getText(node, source).slice(0, 200);
        const routeMatch = fullCallee.match(/Route::(get|post|put|patch|delete|any|match)\s*\(\s*['"]([^'"]*)['"]/);
        if (routeMatch) {
          entryPoints.push({
            type: 'http',
            method: routeMatch[1],
            line: node.startPosition.row + 1,
            handler: null,
            route: routeMatch[2],
          });
        }
      }
    }

    // use statements
    if (node.type === 'namespace_use_declaration') {
      imports.push({
        module: getText(node, source).replace(/^use\s+/, '').replace(/;\s*$/, ''),
        line: node.startPosition.row + 1,
      });
    }
  });

  return { functions, calls, entryPoints, imports };
}

function extractPHPParams(node, source) {
  const params = node.childForFieldName('parameters') || node.namedChildren.find(c => c.type === 'formal_parameters');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'simple_parameter' || p.type === 'property_promotion_parameter')
    .map(p => {
      const nameNode = p.childForFieldName('name');
      return nameNode ? getText(nameNode, source) : getText(p, source);
    })
    .filter(Boolean);
}

function isLaravelControllerMethod(node, source) {
  let parent = node.parent;
  while (parent) {
    if (parent.type === 'class_declaration') {
      const nameNode = parent.childForFieldName('name');
      if (nameNode && getText(nameNode, source).endsWith('Controller')) return true;
      const baseClause = parent.childForFieldName('base_clause');
      if (baseClause && getText(baseClause, source).match(/Controller/)) return true;
    }
    parent = parent.parent;
  }
  return false;
}

function getPHPAttributes(node, source) {
  const attrs = [];
  let prev = node.previousNamedSibling;
  while (prev && prev.type === 'attribute_list') {
    attrs.push(getText(prev, source));
    prev = prev.previousNamedSibling;
  }
  return attrs;
}

// ─── Dart extractor ───

function extractDart(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'function_signature' || node.type === 'method_signature') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        const name = getText(nameNode, source);
        const parent = node.parent;
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: (parent?.endPosition?.row || node.endPosition.row) + 1,
          type: node.type === 'method_signature' ? 'method' : 'function',
        });

        if (name === 'main') {
          entryPoints.push({
            type: 'cli',
            method: 'main',
            line: node.startPosition.row + 1,
            handler: 'main',
            route: null,
          });
        }

        // Flutter lifecycle: initState, dispose, build, didChangeDependencies
        if (['initState', 'dispose', 'build', 'didChangeDependencies', 'didUpdateWidget', 'deactivate'].includes(name)) {
          if (isInsideFlutterWidget(node, source)) {
            entryPoints.push({
              type: 'flutter_lifecycle',
              method: name,
              line: node.startPosition.row + 1,
              handler: name,
              route: null,
            });
          }
        }
      }
    }

    // Dart class extends StatefulWidget/StatelessWidget
    if (node.type === 'class_definition') {
      const nameNode = node.childForFieldName('name');
      const superclass = node.childForFieldName('superclass');
      if (superclass) {
        const superText = getText(superclass, source);
        if (superText.match(/(StatefulWidget|StatelessWidget|State)\b/)) {
          entryPoints.push({
            type: 'flutter_widget',
            method: superText.match(/(StatefulWidget|StatelessWidget|State)/)?.[1] || 'Widget',
            line: node.startPosition.row + 1,
            handler: nameNode ? getText(nameNode, source) : null,
            route: null,
          });
        }
      }
    }

    // Dart shelf/dart_frog route handlers
    if (node.type === 'function_body' || node.type === 'expression_function_body') {
      // File-based routing: routes/<path>/index.dart
      if (filePath.match(/routes\/.*\.dart$/)) {
        entryPoints.push({
          type: 'http',
          method: 'file_route',
          line: 1,
          handler: 'default',
          route: filePath.replace(/^.*routes/, '').replace(/\/index\.dart$/, '').replace(/\.dart$/, ''),
        });
      }
    }

    if (node.type === 'import_directive' || node.type === 'import_or_export') {
      const uriNode = node.namedChildren.find(c => c.type === 'dotted_identifier_list' || c.type === 'uri');
      if (uriNode) {
        imports.push({
          module: getText(uriNode, source).replace(/['"]/g, ''),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

function isInsideFlutterWidget(node, source) {
  let parent = node.parent;
  while (parent) {
    if (parent.type === 'class_definition') {
      const superclass = parent.childForFieldName('superclass');
      if (superclass && getText(superclass, source).match(/(State|StatefulWidget|StatelessWidget)\b/)) return true;
    }
    parent = parent.parent;
  }
  return false;
}

// ─── Solidity extractor ───

function extractSolidity(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'function_definition') {
      const nameNode = node.childForFieldName('name');
      const name = nameNode ? getText(nameNode, source) : null;
      const visibility = getSolidityVisibility(node, source);

      if (name) {
        functions.push({
          name,
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'function',
          params: getSolidityParams(node, source),
        });

        // Public/external functions are entry points (callable from outside)
        if (visibility === 'public' || visibility === 'external') {
          entryPoints.push({
            type: 'web3_function',
            method: visibility,
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }

        // Payable functions handle ETH transfers
        if (getSolidityModifiers(node, source).includes('payable')) {
          entryPoints.push({
            type: 'web3_payable',
            method: 'payable',
            line: node.startPosition.row + 1,
            handler: name,
            route: null,
          });
        }
      }
    }

    // Constructor
    if (node.type === 'constructor_definition') {
      functions.push({
        name: 'constructor',
        line: node.startPosition.row + 1,
        endLine: node.endPosition.row + 1,
        type: 'constructor',
      });
      entryPoints.push({
        type: 'web3_constructor',
        method: 'constructor',
        line: node.startPosition.row + 1,
        handler: 'constructor',
        route: null,
      });
    }

    // Fallback and receive functions
    if (node.type === 'fallback_receive_definition') {
      const kind = getText(node, source).match(/^(fallback|receive)/)?.[1] || 'fallback';
      functions.push({
        name: kind,
        line: node.startPosition.row + 1,
        endLine: node.endPosition.row + 1,
        type: kind,
      });
      entryPoints.push({
        type: 'web3_fallback',
        method: kind,
        line: node.startPosition.row + 1,
        handler: kind,
        route: null,
      });
    }

    // Contract declaration
    if (node.type === 'contract_declaration') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        entryPoints.push({
          type: 'web3_contract',
          method: 'contract',
          line: node.startPosition.row + 1,
          handler: getText(nameNode, source),
          route: null,
        });
      }
    }

    // Event definitions (structural fact — these are the contract's public interface)
    if (node.type === 'event_definition') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        entryPoints.push({
          type: 'web3_event',
          method: 'event',
          line: node.startPosition.row + 1,
          handler: getText(nameNode, source),
          route: null,
        });
      }
    }

    // Modifier definitions
    if (node.type === 'modifier_definition') {
      const nameNode = node.childForFieldName('name');
      if (nameNode) {
        functions.push({
          name: getText(nameNode, source),
          line: node.startPosition.row + 1,
          endLine: node.endPosition.row + 1,
          type: 'modifier',
        });
      }
    }

    if (node.type === 'call_expression' || node.type === 'function_call') {
      const funcNode = node.childForFieldName('function') || node.namedChildren[0];
      if (funcNode) {
        const callee = getText(funcNode, source);
        calls.push({ callee, line: node.startPosition.row + 1 });
      }
    }

    // Import directives
    if (node.type === 'import_directive') {
      const pathNode = node.namedChildren.find(c => c.type === 'string' || c.type === 'import_path');
      if (pathNode) {
        imports.push({
          module: getText(pathNode, source).replace(/['"]/g, ''),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

function getSolidityVisibility(node, source) {
  const text = getText(node, source);
  if (text.match(/\bexternal\b/)) return 'external';
  if (text.match(/\bpublic\b/)) return 'public';
  if (text.match(/\binternal\b/)) return 'internal';
  if (text.match(/\bprivate\b/)) return 'private';
  return 'public';
}

function getSolidityModifiers(node, source) {
  const text = getText(node, source).slice(0, 200);
  const mods = [];
  if (text.match(/\bpayable\b/)) mods.push('payable');
  if (text.match(/\bview\b/)) mods.push('view');
  if (text.match(/\bpure\b/)) mods.push('pure');
  return mods;
}

function getSolidityParams(node, source) {
  const params = node.childForFieldName('parameters') || node.namedChildren.find(c => c.type === 'parameter_list');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'parameter')
    .map(p => {
      const nameNode = p.childForFieldName('name');
      return nameNode ? getText(nameNode, source) : getText(p, source);
    })
    .filter(Boolean);
}

// ─── Elixir extractor ───

function extractElixir(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    if (node.type === 'call') {
      const target = node.childForFieldName('target') || node.namedChildren[0];
      if (!target) return;
      const callee = getText(target, source);

      // def/defp function definitions
      if (callee === 'def' || callee === 'defp') {
        const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'arguments');
        if (args && args.namedChildren[0]) {
          const funcCall = args.namedChildren[0];
          let funcName = null;
          if (funcCall.type === 'call') {
            const funcTarget = funcCall.childForFieldName('target') || funcCall.namedChildren[0];
            funcName = funcTarget ? getText(funcTarget, source) : null;
          } else {
            funcName = getText(funcCall, source).split('(')[0].trim();
          }
          if (funcName) {
            functions.push({
              name: funcName,
              line: node.startPosition.row + 1,
              endLine: node.endPosition.row + 1,
              type: callee === 'def' ? 'public_function' : 'private_function',
            });
          }
        }
      }

      // Phoenix routes: get "/path", Controller, :action
      if (['get', 'post', 'put', 'patch', 'delete', 'resources', 'pipe_through', 'scope', 'forward'].includes(callee)) {
        if (filePath.match(/router\.ex$/)) {
          const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'arguments');
          const routeArg = args?.namedChildren[0];
          const route = routeArg ? getText(routeArg, source).replace(/['"]/g, '').slice(0, 80) : null;
          if (['get', 'post', 'put', 'patch', 'delete', 'resources'].includes(callee)) {
            entryPoints.push({
              type: callee === 'resources' ? 'http_resource' : 'http',
              method: callee === 'resources' ? 'restful' : callee,
              line: node.startPosition.row + 1,
              handler: null,
              route,
            });
          }
        }
      }

      // Phoenix LiveView: mount/3, handle_event/3, handle_info/2
      if (['mount', 'handle_event', 'handle_info', 'handle_params', 'handle_call', 'handle_cast', 'init'].includes(callee)) {
        // These are lifecycle callbacks only if they're def definitions
      }

      // defmodule
      if (callee === 'defmodule') {
        const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'arguments');
        if (args?.namedChildren[0]) {
          const moduleName = getText(args.namedChildren[0], source).split(/\s/)[0];

          // Phoenix controllers
          if (moduleName.match(/Controller$/)) {
            entryPoints.push({
              type: 'phoenix_controller',
              method: 'controller',
              line: node.startPosition.row + 1,
              handler: moduleName,
              route: null,
            });
          }

          // Phoenix LiveView
          if (moduleName.match(/Live$/)) {
            entryPoints.push({
              type: 'phoenix_liveview',
              method: 'liveview',
              line: node.startPosition.row + 1,
              handler: moduleName,
              route: null,
            });
          }

          // GenServer
          const body = getText(node, source).slice(0, 500);
          if (body.match(/use\s+GenServer/)) {
            entryPoints.push({
              type: 'genserver',
              method: 'genserver',
              line: node.startPosition.row + 1,
              handler: moduleName,
              route: null,
            });
          }
        }
      }

      // General calls
      if (!['def', 'defp', 'defmodule', 'defmacro', 'do', 'end', 'use', 'import', 'alias', 'require'].includes(callee)) {
        calls.push({ callee, line: node.startPosition.row + 1 });
      }

      // Imports: use, import, alias, require
      if (['use', 'import', 'alias', 'require'].includes(callee)) {
        const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'arguments');
        if (args?.namedChildren[0]) {
          imports.push({
            module: getText(args.namedChildren[0], source).split(/\s/)[0],
            line: node.startPosition.row + 1,
          });
        }
      }
    }
  });

  // Phoenix LiveView lifecycle functions (look for def mount, def handle_event, etc.)
  const lifecycleFuncs = functions.filter(f =>
    ['mount', 'handle_event', 'handle_info', 'handle_params', 'handle_call', 'handle_cast', 'init', 'terminate'].includes(f.name)
    && f.type === 'public_function'
  );
  for (const lf of lifecycleFuncs) {
    entryPoints.push({
      type: 'elixir_callback',
      method: lf.name,
      line: lf.line,
      handler: lf.name,
      route: null,
    });
  }

  return { functions, calls, entryPoints, imports };
}

// ─── HCL (Terraform) extractor ───

function extractHCL(rootNode, source, filePath) {
  const functions = [];
  const calls = [];
  const entryPoints = [];
  const imports = [];

  walkNode(rootNode, (node) => {
    // Terraform blocks: resource, data, module, provider, variable, output, locals
    if (node.type === 'block') {
      const children = [];
      for (let i = 0; i < node.namedChildCount; i++) {
        children.push(node.namedChild(i));
      }

      const identifiers = children.filter(c => c.type === 'identifier');
      const strings = children.filter(c => c.type === 'string_lit');

      if (identifiers.length > 0) {
        const blockType = getText(identifiers[0], source);
        const blockLabel = strings[0] ? getText(strings[0], source).replace(/['"]/g, '') : (identifiers[1] ? getText(identifiers[1], source) : null);
        const blockName = identifiers[1] ? getText(identifiers[1], source) : null;

        if (blockType === 'resource') {
          entryPoints.push({
            type: 'terraform_resource',
            method: 'resource',
            line: node.startPosition.row + 1,
            handler: blockName || blockLabel,
            route: blockLabel,
          });
          functions.push({
            name: `resource.${blockLabel}.${blockName || 'unnamed'}`,
            line: node.startPosition.row + 1,
            endLine: node.endPosition.row + 1,
            type: 'resource',
          });
        } else if (blockType === 'data') {
          entryPoints.push({
            type: 'terraform_data',
            method: 'data',
            line: node.startPosition.row + 1,
            handler: blockName || blockLabel,
            route: blockLabel,
          });
        } else if (blockType === 'module') {
          entryPoints.push({
            type: 'terraform_module',
            method: 'module',
            line: node.startPosition.row + 1,
            handler: blockLabel,
            route: null,
          });
        } else if (blockType === 'provider') {
          entryPoints.push({
            type: 'terraform_provider',
            method: 'provider',
            line: node.startPosition.row + 1,
            handler: blockLabel,
            route: null,
          });
        } else if (blockType === 'variable') {
          entryPoints.push({
            type: 'terraform_variable',
            method: 'variable',
            line: node.startPosition.row + 1,
            handler: blockLabel,
            route: null,
          });
        } else if (blockType === 'output') {
          entryPoints.push({
            type: 'terraform_output',
            method: 'output',
            line: node.startPosition.row + 1,
            handler: blockLabel,
            route: null,
          });
        }
      }
    }

    // Function calls in HCL expressions
    if (node.type === 'function_call') {
      const nameNode = node.childForFieldName('function') || node.namedChildren[0];
      if (nameNode) {
        calls.push({
          callee: getText(nameNode, source),
          line: node.startPosition.row + 1,
        });
      }
    }
  });

  return { functions, calls, entryPoints, imports };
}

// ─── Shared helpers ───

function getGenericCallArguments(node, source) {
  const args = node.childForFieldName('arguments')
    || node.namedChildren.find(c =>
      c.type === 'arguments' || c.type === 'argument_list'
      || c.type === 'call_suffix' || c.type === 'value_arguments'
    );
  if (!args) return [];
  return args.namedChildren
    .filter(c => c.type !== 'comment')
    .map(c => ({ expr: getText(c, source).slice(0, 80), type: c.type }));
}

// ─── Helpers ───

function walkNode(node, callback) {
  callback(node);
  for (let i = 0; i < node.childCount; i++) {
    walkNode(node.child(i), callback);
  }
}

function getText(node, source) {
  return source.slice(node.startIndex, node.endIndex);
}

function isFunctionNode(node) {
  return [
    'function_declaration', 'function', 'arrow_function',
    'method_definition', 'generator_function_declaration',
  ].includes(node.type);
}

function getFunctionName(node, source) {
  const nameNode = node.childForFieldName('name');
  if (nameNode) return getText(nameNode, source);
  const parent = node.parent;
  if (parent?.type === 'variable_declarator') {
    const id = parent.childForFieldName('name');
    if (id) return getText(id, source);
  }
  if (parent?.type === 'pair') {
    const key = parent.childForFieldName('key');
    if (key) return getText(key, source);
  }
  return null;
}

function extractParams(node, source) {
  const params = node.childForFieldName('parameters');
  if (!params) return [];
  return params.namedChildren.map(p => getText(p, source)).filter(Boolean);
}

function extractPythonParams(node, source) {
  const params = node.childForFieldName('parameters');
  if (!params) return [];
  return params.namedChildren
    .filter(p => p.type === 'identifier' || p.type === 'typed_parameter')
    .map(p => getText(p, source))
    .filter(Boolean);
}

function getCallTarget(node, source) {
  const fn = node.childForFieldName('function');
  if (!fn) return null;
  return getText(fn, source);
}

function getCallArguments(node, source) {
  const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'arguments');
  if (!args) return [];
  return args.namedChildren
    .filter(c => c.type !== 'comment')
    .map(c => ({ expr: getText(c, source).slice(0, 80), type: c.type }));
}

function getPythonCallArguments(node, source) {
  const argList = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'argument_list');
  if (!argList) return [];
  return argList.namedChildren
    .filter(c => c.type !== 'comment')
    .map(c => ({ expr: getText(c, source).slice(0, 80), type: c.type }));
}

// HTTP 메서드명(.get/.post/...)을 가진 호출 중 실제 라우터 등록만 라우트로 본다.
// config.get / redis.get / cache.get / Map.get 등은 라우트가 아니라 조회 호출이므로
// 소스(entry point) 오탐을 만든다(P2-5). 수신자 denylist로 차단하되, 커스텀 라우터명
// (authRouter.get 등)은 유지해 recall 손실을 피한다.
const NON_ROUTER_RECEIVERS = new Set([
  'config', 'redis', 'cache', 'memcached', 'map', 'set', 'weakmap', 'store', 'state',
  'localstorage', 'sessionstorage', 'storage', 'fs', 'promises', 'path',
  'axios', 'http', 'https', 'got', 'fetch', 'superagent', 'request', 'client',
  'window', 'document', 'navigator', 'process', 'env', 'json', 'object', 'reflect',
  'headers', 'params', 'query', 'session', 'cookies', 'db', 'database', 'model', 'repo',
  'repository', 'this', 'self', 'obj', 'options', 'opts', 'settings', 'prefs',
]);

// 라우터로 볼 수신자: 정확한 관용명 또는 ...Router/...App/...Routes 접미.
function looksLikeRouter(receiver) {
  const r = receiver.toLowerCase();
  if (['app', 'router', 'server', 'api', 'route', 'routes', 'express'].includes(r)) return true;
  return r.endsWith('router') || r.endsWith('routes') || (r.endsWith('app') && r.length > 3);
}

function isRouteRegistration(callee) {
  if (!callee) return false;
  const m = String(callee).match(
    /^(.+)\.(get|post|put|patch|delete|all|use|Get|Post|Put|Patch|Delete|Handle|HandleFunc)$/
  );
  if (!m) return false;
  const receiver = m[1].split('.').pop();
  const method = m[2].toLowerCase();
  // get/use/all은 lookup(config.get, map.get, cache.use)과 구분 불가 → 라우터 수신자만 인정.
  if (method === 'get' || method === 'use' || method === 'all') {
    return looksLikeRouter(receiver);
  }
  // post/put/patch/delete + Go(Handle/HandleFunc)는 lookup에 거의 없음 → denylist만 적용.
  return !NON_ROUTER_RECEIVERS.has(receiver.toLowerCase());
}

function extractHttpMethod(callee) {
  const match = callee.match(/\.(get|post|put|patch|delete|all|use|Get|Post|Put|Patch|Delete|Handle)/);
  return match ? match[1].toLowerCase() : 'unknown';
}

function extractHandlerName(node, source) {
  const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'arguments');
  if (!args) return null;
  const lastArg = args.namedChildren[args.namedChildren.length - 1];
  if (!lastArg) return null;
  if (lastArg.type === 'identifier' || lastArg.type === 'member_expression') {
    return getText(lastArg, source);
  }
  return null;
}

function extractRouteString(node, source) {
  const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'arguments');
  if (!args) return null;
  const firstArg = args.namedChildren[0];
  if (firstArg?.type === 'string' || firstArg?.type === 'template_string') {
    return getText(firstArg, source).replace(/['"`]/g, '');
  }
  return null;
}

function extractImportJS(node, source) {
  if (node.type === 'import_statement') {
    const srcNode = node.childForFieldName('source');
    if (srcNode) {
      return { module: getText(srcNode, source).replace(/['"]/g, ''), line: node.startPosition.row + 1 };
    }
  }
  if (node.type === 'call_expression') {
    const fn = node.childForFieldName('function');
    if (fn && getText(fn, source) === 'require') {
      const args = node.childForFieldName('arguments') || node.namedChildren.find(c => c.type === 'arguments');
      if (args?.namedChildren[0]) {
        return { module: getText(args.namedChildren[0], source).replace(/['"]/g, ''), line: node.startPosition.row + 1 };
      }
    }
  }
  return null;
}

function getDecorators(node, source) {
  const decorators = [];
  let prev = node.previousNamedSibling;
  while (prev && prev.type === 'decorator') {
    decorators.push(getText(prev, source));
    prev = prev.previousNamedSibling;
  }
  return decorators;
}

function resolveImportEdges(graph) {
  for (const [file, imps] of graph.imports) {
    for (const imp of imps) {
      if (imp.module.startsWith('.')) {
        const resolvedBase = path.join(path.dirname(file), imp.module).replace(/\\/g, '/');
        const candidates = [resolvedBase, `${resolvedBase}.js`, `${resolvedBase}.ts`, `${resolvedBase}/index.js`, `${resolvedBase}/index.ts`];
        for (const [nodeKey] of graph.nodes) {
          const nodeFile = nodeKey.split(':')[0];
          if (candidates.some(c => nodeFile === c || nodeFile.startsWith(resolvedBase + '/'))) {
            imp.resolvedFile = nodeFile;
            break;
          }
        }
      }
    }
  }
}

function serializeGraph(graph) {
  const nodes = {};
  for (const [key, val] of graph.nodes) nodes[key] = val;
  const imports = {};
  for (const [key, val] of graph.imports) imports[key] = val;

  return {
    nodes,
    edges: graph.edges,
    entryPoints: graph.entryPoints,
    imports,
    assignments: graph.assignments || [],
    stats: {
      total_functions: graph.nodes.size,
      total_calls: graph.edges.length,
      total_entry_points: graph.entryPoints.length,
    },
  };
}

module.exports = { extractCallGraph };
