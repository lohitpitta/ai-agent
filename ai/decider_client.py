"""
Strands Decider 2B HTTP client for decision-making.
"""

import os
import requests
from typing import Dict, Any, Optional, List
from enum import Enum


class DecisionOutcome(Enum):
    """Possible decision outcomes."""
    CONTINUE_TO_REPORT = "CONTINUE_TO_REPORT"
    VERIFY_WITH_ANOTHER_SOURCE = "VERIFY_WITH_ANOTHER_SOURCE"
    FLAG_FOR_REVIEW = "FLAG_FOR_REVIEW"


class DeciderClient:
    """Client for Strands Decider 2B HTTP server."""
    
    def __init__(self):
        self.server_url = os.getenv("DECIDER_SERVER_URL", "http://localhost:8000")
        self.endpoint = f"{self.server_url}/v1/systemone"
        self.timeout = int(os.getenv("DECIDER_TIMEOUT", "30"))
    
    def make_decision(
        self,
        state: str,
        options: List[str]
    ) -> Optional[DecisionOutcome]:
        """
        Make a decision using Decider 2B.
        
        Args:
            state: Context text for the decision
            options: List of decision options (must be exactly 3 for our use case)
            
        Returns:
            DecisionOutcome or None if decision failed
        """
        if len(options) != 3:
            raise ValueError("Decider requires exactly 3 options")
        
        payload = {
            "state": state,
            "questions": {
                "decision": {
                    "type": "choice",
                    "instructions": f"Choose the best action: {', '.join(options)}"
                }
            }
        }
        
        try:
            response = requests.post(
                self.endpoint,
                json=payload,
                headers={"content-type": "application/json"},
                timeout=self.timeout
            )
            
            if response.status_code != 200:
                print(f"Decider API error: {response.status_code}")
                return None
            
            data = response.json()
            answer = data.get("answers", {}).get("decision", {})
            
            # Extract the chosen option
            choice = answer.get("choice")
            if choice:
                # Map the choice string to DecisionOutcome enum
                choice_map = {opt: DecisionOutcome(opt) for opt in options}
                return choice_map.get(choice)
            
            return None
            
        except requests.exceptions.RequestException as e:
            print(f"Decider request failed: {e}")
            return None
    
    def is_available(self) -> bool:
        """Check if Decider server is available."""
        try:
            response = requests.get(
                self.server_url,
                timeout=5
            )
            return response.status_code == 200
        except requests.exceptions.RequestException:
            return False
