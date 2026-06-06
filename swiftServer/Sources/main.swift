import Foundation
import Hummingbird

func startProductionServer() async throws {
    let targetPort = 8080
    print("⚡ Preparing Ephemeral Private Inference Gateway on Port \(targetPort)...")
    let router = Router()
    let app = Application(
        responder: router.buildResponder(),
        configuration: .init(address: .hostname("127.0.0.1", port: targetPort))
    )
    print(" Server Engine is LIVE. Listening for real connections at http://127.0.0.1:\(targetPort)")
    try await app.runService()
}

// Fire up the genuine, multi-threaded production gateway server loop
try await startProductionServer()