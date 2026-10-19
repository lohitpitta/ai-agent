from dotenv import load_dotenv
load_dotenv()

from ai.bedrock_client import BedrockClient

client = BedrockClient()

print("Region:", client.region)
print("Model:", client.model_id)

if not client.is_available():
    print("ERROR: Bedrock client initialization failed.")
else:
    try:
        response = client.client.converse(
            modelId=client.model_id,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {"text": "Reply with exactly: DepGuard AI test successful"}
                    ]
                }
            ],
            inferenceConfig={
                "maxTokens": 50,
                "temperature": 0
            }
        )

        answer = response["output"]["message"]["content"][0]["text"]
        print("\nBedrock Response:", answer)
        print("\nSUCCESS: Actual model API call worked!")

    except Exception as e:
        print("\nAPI CALL FAILED:")
        print(type(e).__name__, str(e))