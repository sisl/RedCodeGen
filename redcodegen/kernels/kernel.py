from abc import ABC, abstractmethod


class Kernel(ABC):
    """A function t' ~ g(. | t) use do sample the next step of MCMC."""

    @abstractmethod
    def sample(self, tau: str) -> str:
        """Sample a new trajectory tau' given the current trajectory tau.

        Args:
            tau (str): The current trajectory.

        Returns:
            str: The sampled trajectory tau'.
        """
        pass

    @abstractmethod
    def condition(self, tau: str, tau_prime: str) -> float:
        """Compute the LOG conditional probability of tau_prime given tau.

        Args:
            tau (str): The current trajectory.
            tau_prime (str): The proposed trajectory.

        Returns:
            float: The conditional probability log(g(tau' | tau)).
        """

        pass


