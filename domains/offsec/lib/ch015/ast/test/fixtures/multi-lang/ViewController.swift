import Foundation
import UIKit

class UserService {
    func fetchUser(id: String) -> User? {
        let url = URL(string: "https://api.example.com/users/\(id)")!
        let data = try? Data(contentsOf: url)
        return parseUser(data: data)
    }

    func parseUser(data: Data?) -> User? {
        guard let data = data else { return nil }
        return try? JSONDecoder().decode(User.self, from: data)
    }

    func deleteUser(id: String) {
        let query = "DELETE FROM users WHERE id = '\(id)'"
        database.execute(query)
    }
}
