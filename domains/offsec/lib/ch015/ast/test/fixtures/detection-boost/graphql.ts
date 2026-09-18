import { Resolver, Query, Mutation, Arg } from 'type-graphql';

@Resolver()
export class UserResolver {
  @Query(() => String)
  async user(@Arg('id') id: string): Promise<string> {
    return findUser(id);
  }

  @Mutation(() => Boolean)
  async deleteUser(@Arg('id') id: string): Promise<boolean> {
    return removeUser(id);
  }
}
