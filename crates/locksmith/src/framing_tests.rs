use super::*;
use serde_json::Value;

#[tokio::test]
async fn invalid_lengths_fail_with_only_a_header() {
    for length in [0, 1, 31, MAX_FRAME_BODY + 1, u32::MAX] {
        let (mut peer, mut reader) = tokio::io::duplex(4);
        peer.write_u32(length).await.unwrap();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            receive::<Value>(&mut reader),
        )
        .await
        .expect("invalid lengths must not wait for a body");
        assert!(
            matches!(result, Err(ReceiveError::InvalidFrameLength { length: actual, .. }) if actual == length)
        );
    }
}

#[tokio::test]
async fn maximum_frame_body_roundtrips() {
    let value = "x".repeat(MAX_FRAME_BODY as usize - 32 - 2);
    let frame = keyfork_frame::try_encode(&serde_json::to_vec(&value).unwrap()).unwrap();
    assert_eq!(frame.len(), MAX_FRAME_BODY as usize + 4);
    assert_eq!(
        receive::<String>(&mut frame.as_slice()).await.unwrap(),
        value
    );
}

#[tokio::test]
async fn protocol_messages_fit_and_preserve_serialization() {
    let messages = [
        serde_json::to_value(models::GeneratePublicKeyRequest {
            nonce: "ab".repeat(32),
        })
        .unwrap(),
        serde_json::to_value(models::GeneratePublicKeyResponse {
            attestation: include_bytes!("../tests/data/aws-test.cbor").to_vec(),
        })
        .unwrap(),
        serde_json::to_value(models::SendSignedEncryptedShardRequest {
            signed_payload: serde_json::to_string(&models::SendEncryptedShardRequest {
                encrypted_payload: "ab".repeat(512),
                public_key: [7; 32],
            })
            .unwrap(),
            signature: "armored detached signature".into(),
        })
        .unwrap(),
        serde_json::to_value(models::SendSignedEncryptedShardResponse::Accepted { remaining: 1 })
            .unwrap(),
        serde_json::to_value(models::SendSignedEncryptedShardResponse::Rejected {
            reason: "invalid share".into(),
        })
        .unwrap(),
    ];
    for value in messages {
        let frame = keyfork_frame::try_encode(&serde_json::to_vec(&value).unwrap()).unwrap();
        assert!(frame.len() - 4 <= MAX_FRAME_BODY as usize);
        assert_eq!(
            receive::<Value>(&mut frame.as_slice()).await.unwrap(),
            value
        );
    }
}

#[tokio::test]
async fn truncated_corrupt_and_empty_frames_fail_without_panicking() {
    let mut frame = keyfork_frame::try_encode(b"{}").unwrap();
    for mut bytes in [&frame[..2], &frame[..frame.len() - 1]] {
        assert!(matches!(
            receive::<Value>(&mut bytes).await,
            Err(ReceiveError::ReceivePayload {
                source: keyfork_frame::DecodeError::Io(_)
            })
        ));
    }
    frame[4] ^= 1;
    assert!(matches!(
        receive::<Value>(&mut frame.as_slice()).await,
        Err(ReceiveError::ReceivePayload {
            source: keyfork_frame::DecodeError::BadChecksum(_, _)
        })
    ));
    let empty = keyfork_frame::try_encode(b"").unwrap();
    assert!(matches!(
        receive::<Value>(&mut empty.as_slice()).await,
        Err(ReceiveError::DeserializePayload { .. })
    ));
}

#[tokio::test]
async fn consecutive_frames_are_not_overread() {
    let mut frames = keyfork_frame::try_encode(b"1").unwrap();
    frames.extend(keyfork_frame::try_encode(b"2").unwrap());
    let mut reader = frames.as_slice();
    assert_eq!(receive::<u8>(&mut reader).await.unwrap(), 1);
    assert_eq!(receive::<u8>(&mut reader).await.unwrap(), 2);
    assert!(reader.is_empty());
}
