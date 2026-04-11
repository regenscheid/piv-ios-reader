import SwiftUI
import UserNotifications

class AppDelegate: NSObject, UIApplicationDelegate {
    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        // Set notification delegate early so cold-launch notifications are captured
        UNUserNotificationCenter.current().delegate = TokenRequestHandler.shared
        print("[APP] didFinishLaunching, notification delegate set")
        return true
    }
}

@main
struct PIVReaderApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate
    @StateObject private var tokenHandler = TokenRequestHandler.shared

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(tokenHandler)
        }
    }
}
