"""
Amazon Bedrock client for decision-making fallback and explanations.
Uses Amazon Nova Micro (amazon.nova-micro-v1:0) via the Bedrock Converse API.
"""

import os
import json
import boto3
from typing import Dict, Any, Optional, List
from enum import Enum

from ai.decider_client import DecisionOutcome


class BedrockClient:
    """Client for Amazon Bedrock (fallback for decision-making)."""
    
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "ap-southeast-2")
        self.model_id = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-micro-v1:0")

        # Explicitly read AWS credentials from environment variables
        # (set via .env file loaded by python-dotenv in app.py)
        aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
        aws_secret_key = os.getenv("AWS_SECRET_ACCESS_KEY")
        aws_session_token = os.getenv("AWS_SESSION_TOKEN") or None

        if not aws_access_key or not aws_secret_key:
            print(
                "WARNING: AWS_ACCESS_KEY_ID or AWS_SECRET_ACCESS_KEY not set. "
                "Bedrock client will not be available."
            )
            self.client = None
            return

        # Initialize Bedrock runtime client with explicit credentials
        try:
            self.client = boto3.client(
                "bedrock-runtime",
                region_name=self.region,
                aws_access_key_id=aws_access_key,
                aws_secret_access_key=aws_secret_key,
                aws_session_token=aws_session_token,
            )
        except Exception as e:
            print(f"Failed to initialize Bedrock client: {e}")
            self.client = None
    
    def make_decision(
        self,
        state: str,
        options: List[str]
    ) -> Optional[DecisionOutcome]:
        """
        Make a decision using Bedrock (fallback).
        
        Args:
            state: Context text for the decision
            options: List of decision options (must be exactly 3)
            
        Returns:
            DecisionOutcome or None if decision failed
        """
        if not self.client:
            return None
        
        if len(options) != 3:
            raise ValueError("Decision requires exactly 3 options")
        
        # Construct prompt for structured JSON output
        prompt = f"""You are a security vulnerability analyst. Based on the following information, choose the best action.

Context:
{state}

Available actions:
1. CONTINUE_TO_REPORT - The finding is clear and should be included in the report as-is
2. VERIFY_WITH_ANOTHER_SOURCE - The finding needs verification from another source before reporting
3. FLAG_FOR_REVIEW - The finding is ambiguous or requires manual review

Respond with ONLY a JSON object in this exact format:
{{"decision": "ACTION_NAME"}}

Replace ACTION_NAME with one of: CONTINUE_TO_REPORT, VERIFY_WITH_ANOTHER_SOURCE, FLAG_FOR_REVIEW"""
        
        try:
            # Use Converse API (recommended)
            response = self.client.converse(
                modelId=self.model_id,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": prompt}]
                    }
                ],
                inferenceConfig={
                    "maxTokens": 100,
                    "temperature": 0
                }
            )
            
            # Extract response text
            response_text = response["output"]["message"]["content"][0]["text"]
            
            # Parse JSON response
            try:
                result = json.loads(response_text)
                decision_str = result.get("decision")
                
                if decision_str:
                    return DecisionOutcome(decision_str)
            except json.JSONDecodeError:
                print(f"Failed to parse Bedrock JSON response: {response_text}")
            
            return None
            
        except Exception as e:
            print(f"Bedrock decision failed: {e}")
            return None
    
    def generate_explanation(
        self,
        dependency_name: str,
        dependency_version: str,
        advisories: List[Dict[str, Any]],
        evidence: Dict[str, Any]
    ) -> Optional[str]:
        """
        Generate explanation and remediation text using Bedrock.
        
        Args:
            dependency_name: Name of the dependency
            dependency_version: Version of the dependency
            advisories: List of advisory information
            evidence: Collected evidence from various sources
            
        Returns:
            Explanation text or None if generation failed
        """
        if not self.client:
            return None
        
        # Construct prompt grounded in evidence
        prompt = f"""You are a security vulnerability analyst. Provide a brief explanation and remediation guidance for the following vulnerability finding.

Dependency: {dependency_name}@{dependency_version}

Advisories:
{json.dumps(advisories, indent=2)}

Evidence from verification sources:
{json.dumps(evidence, indent=2)}

IMPORTANT:
- Base your response ONLY on the provided evidence
- Do not invent information not present in the evidence
- Keep the explanation concise (2-3 sentences)
- Provide specific remediation steps if available in the evidence
- If evidence is insufficient, state that clearly

Respond with a JSON object in this format:
{{"explanation": "...", "remediation": "..."}}"""
        
        try:
            response = self.client.converse(
                modelId=self.model_id,
                messages=[
                    {
                        "role": "user",
                        "content": [{"text": prompt}]
                    }
                ],
                inferenceConfig={
                    "maxTokens": 500,
                    "temperature": 0.3
                }
            )
            
            response_text = response["output"]["message"]["content"][0]["text"]
            
            try:
                result = json.loads(response_text)
                explanation = result.get("explanation", "")
                remediation = result.get("remediation", "")
                
                if explanation or remediation:
                    return f"Explanation: {explanation}\n\nRemediation: {remediation}"
            except json.JSONDecodeError:
                print(f"Failed to parse Bedrock JSON response: {response_text}")
            
            return None
            
        except Exception as e:
            print(f"Bedrock explanation failed: {e}")
            return None
    
    def is_available(self) -> bool:
        """Check if Bedrock is available."""
        return self.client is not None
