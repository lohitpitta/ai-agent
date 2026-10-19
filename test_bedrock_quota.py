import boto3
from botocore.exceptions import ClientError

client = boto3.client("bedrock-runtime", region_name="ap-southeast-2")

try:
    response = client.converse(
        modelId="amazon.nova-micro-v1:0",
        messages=[
            {
                "role": "user",
                "content": [{"text": "Reply OK"}]
            }
        ],
        inferenceConfig={"maxTokens": 5}
    )
    print("SUCCESS:", response["output"]["message"]["content"][0]["text"])

except ClientError as error:
    print("ERROR CODE:", error.response["Error"]["Code"])
    print("ERROR MESSAGE:", error.response["Error"]["Message"])
    print("REQUEST ID:", error.response["ResponseMetadata"].get("RequestId"))
