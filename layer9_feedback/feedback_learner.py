"""
=============================================================================
LAYER 9: RICH FEEDBACK LEARNING SYSTEM
Module: feedback_learner.py
-----------------------------------------------------------------------------
Problem Solved:
  Learns from past incident containment outcomes, false positives, downtime,
  and operator overrides. Solves static decision-making by creating a
  continuous feedback loop using Exponential Moving Averages (EMA) and rolling
  metrics to adapt utility weights.

  Rich Incident Record:
    - attack_type, threat_score, confidence, selected_action, alternative_actions
    - successful, containment_time, downtime, false_positive_status, operator_override

  Feedback Metrics & Adaptation:
    - Exponential Moving Average (EMA) of success rates per action/attack type
    - Rolling containment time and rolling downtime tracking
    - Adaptive utility weight calibration for future optimization rounds

Inputs:  Rich incident outcome parameters.
Outputs: Updated utility weights, EMA metrics, and persistent feedback history (JSON file).
=============================================================================
"""

import json
import os
from dataclasses import dataclass, asdict
from typing import Dict, Any, List, Optional
from datetime import datetime
from config import FEEDBACK_DATA_PATH, FEEDBACK_LEARNING_RATE, UTILITY_WEIGHTS


@dataclass
class RichIncidentFeedback:
    incident_id: str
    timestamp: str
    scenario: str
    attack_type: str
    plan: Dict[str, str]
    threat_score: float
    confidence: float
    selected_action: str
    alternative_actions: List[str]
    successful: bool
    containment_time_sec: float
    downtime_sec: float
    false_positive_status: bool
    operator_override: bool
    notes: str
    initial_utility_weights: Dict[str, float]
    outcome_metrics: Dict[str, float]


# Alias for backward compatibility
IncidentFeedback = RichIncidentFeedback


class FeedbackLearner:
    """
    Rich Feedback Learning Engine with EMA weight adjustments & rolling metrics.
    """

    def __init__(self, data_path: str = FEEDBACK_DATA_PATH, alpha: float = 0.2):
        self.data_path = data_path
        self.alpha = alpha  # EMA smoothing factor (0.2)
        self.feedback_history: List[RichIncidentFeedback] = []
        self.current_weights = UTILITY_WEIGHTS.copy()
        self.action_ema_success: Dict[str, float] = {}
        self.action_ema_downtime: Dict[str, float] = {}
        self.action_ema_containment: Dict[str, float] = {}
        self._load_feedback()

    def _load_feedback(self):
        if os.path.exists(self.data_path):
            try:
                with open(self.data_path, "r") as f:
                    data = json.load(f)
                for item in data:
                    self.feedback_history.append(RichIncidentFeedback(**item))
                if self.feedback_history:
                    last = self.feedback_history[-1]
                    if "current_weights" in last.outcome_metrics:
                        self.current_weights = last.outcome_metrics["current_weights"]
                    self._recalculate_ema()
            except Exception as e:
                print(f"Error loading feedback history: {e}")

    def save_feedback(self):
        with open(self.data_path, "w") as f:
            json.dump([asdict(fb) for fb in self.feedback_history], f, indent=2)

    def _recalculate_ema(self):
        """Recalculates Exponential Moving Averages across history."""
        for fb in self.feedback_history:
            act = fb.selected_action
            succ = 1.0 if fb.successful and not fb.false_positive_status else 0.0
            dt = fb.downtime_sec
            ct = fb.containment_time_sec

            if act not in self.action_ema_success:
                self.action_ema_success[act] = succ
                self.action_ema_downtime[act] = dt
                self.action_ema_containment[act] = ct
            else:
                self.action_ema_success[act] = (1 - self.alpha) * self.action_ema_success[act] + self.alpha * succ
                self.action_ema_downtime[act] = (1 - self.alpha) * self.action_ema_downtime[act] + self.alpha * dt
                self.action_ema_containment[act] = (1 - self.alpha) * self.action_ema_containment[act] + self.alpha * ct

    def record_feedback(
        self,
        incident_id: str,
        scenario: str,
        plan: Dict[str, str],
        successful: bool,
        attack_type: str = "general_threat",
        threat_score: float = 0.8,
        confidence: float = 0.9,
        selected_action: str = "isolate",
        alternative_actions: Optional[List[str]] = None,
        containment_time_sec: float = 12.0,
        downtime_sec: float = 45.0,
        false_positive_status: bool = False,
        operator_override: bool = False,
        notes: str = "",
        outcome_metrics: Optional[Dict[str, float]] = None,
    ) -> RichIncidentFeedback:
        """
        Records a comprehensive incident outcome and updates weights via EMA.
        """
        metrics = outcome_metrics or {}
        feedback = RichIncidentFeedback(
            incident_id=incident_id,
            timestamp=datetime.now().isoformat(timespec="seconds"),
            scenario=scenario,
            attack_type=attack_type,
            plan=plan,
            threat_score=threat_score,
            confidence=confidence,
            selected_action=selected_action,
            alternative_actions=alternative_actions or [],
            successful=successful,
            containment_time_sec=containment_time_sec,
            downtime_sec=downtime_sec,
            false_positive_status=false_positive_status,
            operator_override=operator_override,
            notes=notes,
            initial_utility_weights=self.current_weights.copy(),
            outcome_metrics=metrics,
        )
        self.feedback_history.append(feedback)
        self._update_weights_ema(feedback)
        
        # Save updated weights into metrics dict for auditability
        feedback.outcome_metrics["current_weights"] = self.current_weights.copy()
        feedback.outcome_metrics["ema_success_rate"] = self.action_ema_success.get(selected_action, 1.0)
        self.save_feedback()
        return feedback

    def _update_weights_ema(self, feedback: RichIncidentFeedback):
        """
        Adapts utility weights using EMA outcome performance.
        """
        lr = FEEDBACK_LEARNING_RATE
        act = feedback.selected_action
        succ = 1.0 if feedback.successful and not feedback.false_positive_status else 0.0

        # Update EMA state
        if act not in self.action_ema_success:
            self.action_ema_success[act] = succ
            self.action_ema_downtime[act] = feedback.downtime_sec
            self.action_ema_containment[act] = feedback.containment_time_sec
        else:
            self.action_ema_success[act] = (1 - self.alpha) * self.action_ema_success[act] + self.alpha * succ
            self.action_ema_downtime[act] = (1 - self.alpha) * self.action_ema_downtime[act] + self.alpha * feedback.downtime_sec
            self.action_ema_containment[act] = (1 - self.alpha) * self.action_ema_containment[act] + self.alpha * feedback.containment_time_sec

        # Weight adaptation rules:
        # 1. False positive -> penalty to containment_effectiveness, increase compliance/business protection
        if feedback.false_positive_status:
            self.current_weights["containment_effectiveness"] *= (1.0 - lr * 1.5)
            self.current_weights["business_impact"] *= (1.0 + lr * 0.5)
            self.current_weights["downtime"] *= (1.0 + lr * 0.5)

        # 2. Operator override -> indicates action was too aggressive
        elif feedback.operator_override:
            self.current_weights["business_impact"] *= (1.0 + lr)
            self.current_weights["containment_effectiveness"] *= (1.0 - lr * 0.5)

        # 3. Successful containment -> reinforce containment weight
        elif feedback.successful:
            self.current_weights["containment_effectiveness"] *= (1.0 + lr * 0.5)

        # 4. Failure to contain -> significantly increase containment requirement
        else:
            self.current_weights["containment_effectiveness"] *= (1.0 + lr * 1.8)

        self._normalize_weights()

    def _normalize_weights(self):
        total = abs(sum(v for v in self.current_weights.values()))
        if total > 0:
            for k in self.current_weights:
                self.current_weights[k] /= total

    def get_current_weights(self) -> Dict[str, float]:
        return self.current_weights.copy()

    def get_rolling_metrics(self) -> Dict[str, Dict[str, float]]:
        return {
            "ema_success": self.action_ema_success.copy(),
            "ema_downtime": self.action_ema_downtime.copy(),
            "ema_containment": self.action_ema_containment.copy(),
        }
