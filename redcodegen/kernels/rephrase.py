import dspy
from redcodegen.kernels import Kernel

class GenerateConditionedPrompt(dspy.Signature):
    """Come up with a rephrased coding task that exercises the same techniques and tools; think about this as an exercise that checks same skills and knowledge; make sure that the new task is meaningfully different such that its not just the first task with names changed, but also make sure the new task excercises the exact sample libraries and skills."""

    task: str = dspy.InputField()
    rephrased_task: str = dspy.OutputField()

class LMRephrasingKernel(Kernel):
    def __init__(self):
        self.kernel = dspy.ChainOfThought(GenerateConditionedPrompt)
        
    def sample(self, tau):
        return self.kernel(task=tau).rephrased_task

    def condition(self, tau, tau_prime):
        """Compute the conditional probability of tau_prime given tau.

        Args:
            tau (str): The current trajectory.
            tau_prime (str): The proposed trajectory.

        Returns:
            float: The conditional probability g(tau' | tau).
        """

        # Generate with logprobs enabled to get probability distribution
        result = self.kernel(task=tau, config={"logprobs": True})
        return sum([i.logprob for i in result.logprobs.content])

