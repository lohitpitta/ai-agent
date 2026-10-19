import boto3
from strands import Agent
from strands.models import BedrockModel


def main():
    print("STEP 1: Checking AWS identity...", flush=True)

    sts = boto3.client("sts", region_name="ap-southeast-2")
    print(sts.get_caller_identity()["Arn"], flush=True)

    print("STEP 2: Creating Bedrock model...", flush=True)

    model = BedrockModel(
        model_id="amazon.nova-micro-v1:0",
        region_name="ap-southeast-2",
    )

    print("STEP 3: Creating Strands Agent...", flush=True)

    agent = Agent(model=model)

    print("STEP 4: Calling agent...", flush=True)

    response = agent("Reply with exactly: Strands agent working")

    print("STEP 5: Agent response:", flush=True)
    print(response, flush=True)


if __name__ == "__main__":
    main()