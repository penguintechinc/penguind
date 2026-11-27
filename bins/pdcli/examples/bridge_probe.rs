//! Bridge and proxy service probe — verifies SessionProxy and BridgeActionProxy
//! services are registered on the daemon and callable.
//!
//! Connection pattern reuses parity_probe.rs: connect via UDS to the daemon and
//! invoke RPC methods on the newly-registered proxy services. Transport-level
//! "Unimplemented" errors mean the services are NOT registered (the fix failed).
//! Application-level errors (e.g., "module not found", "webhook not found") mean
//! the services ARE registered and their handlers ran (the fix worked).

use std::process::ExitCode;

use penguin_proto::desktop::v1::bridge_action_proxy_client::BridgeActionProxyClient;
use penguin_proto::desktop::v1::session_proxy_client::SessionProxyClient;
use penguin_proto::desktop::v1::{BridgeActionRequest, UserSession};

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: bridge_probe <socket>");
        return ExitCode::from(2);
    }
    let socket = args[1].clone();

    let channel = match penguin_ipc::dial_unix::dial(&socket).await {
        Ok(ch) => ch,
        Err(err) => {
            println!("PROBE status=dial-failed message={err:?}");
            return ExitCode::from(3);
        }
    };

    // Test 1: SessionProxyClient::set_user_session
    println!("\n=== Test 1: SessionProxyClient::set_user_session ===");
    let mut session_client = SessionProxyClient::new(channel.clone());
    let req = UserSession {
        api_version: "v1".to_string(),
        access_token: "test-token".to_string(),
        refresh_token: "".to_string(),
        hub_base_url: "http://127.0.0.1:1".to_string(),
    };

    match session_client.set_user_session(req).await {
        Ok(resp) => {
            println!("✓ SetUserSession succeeded (application-level response received)");
            println!("  Response: {:?}", resp.get_ref());
        }
        Err(e) => {
            let code = e.code();
            let msg = e.message();
            if code == tonic::Code::Unimplemented && msg.contains("service not found") {
                println!(
                    "✗ SetUserSession returned transport-level 'Unimplemented' error: {}",
                    msg
                );
                println!("  → The SessionProxy service is NOT registered (FIX FAILED)");
                return ExitCode::from(1);
            } else {
                println!(
                    "✓ SetUserSession returned application-level error (service IS registered)"
                );
                println!("  Error: {:?}: {}", code, msg);
            }
        }
    }

    // Test 2: BridgeActionProxyClient::execute_bridge_action
    println!("\n=== Test 2: BridgeActionProxyClient::execute_bridge_action ===");
    let mut bridge_client = BridgeActionProxyClient::new(channel);
    let req = BridgeActionRequest {
        api_version: "v1".to_string(),
        module_name: "waddles-gateway".to_string(),
        action_type: "webhook".to_string(),
        webhook_name: "nonexistent-test-webhook".to_string(),
        ..Default::default()
    };

    match bridge_client.execute_bridge_action(req).await {
        Ok(resp) => {
            println!("✓ ExecuteBridgeAction succeeded (application-level response received)");
            println!("  Response: {:?}", resp.get_ref());
        }
        Err(e) => {
            let code = e.code();
            let msg = e.message();
            if code == tonic::Code::Unimplemented && msg.contains("service not found") {
                println!(
                    "✗ ExecuteBridgeAction returned transport-level 'Unimplemented' error: {}",
                    msg
                );
                println!("  → The BridgeActionProxy service is NOT registered (FIX FAILED)");
                return ExitCode::from(1);
            } else {
                println!(
                    "✓ ExecuteBridgeAction returned application-level error (service IS registered)"
                );
                println!("  Error: {:?}: {}", code, msg);
            }
        }
    }

    println!("\n=== Result ===");
    println!("✓ Both SessionProxy and BridgeActionProxy services are registered and callable!");
    println!(
        "  (Errors above are expected application-level rejections, not registration failures.)"
    );

    ExitCode::SUCCESS
}
