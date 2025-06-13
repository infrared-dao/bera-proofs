"""
Base SSZ Container Classes

This module provides the base classes and interfaces for SSZ containers.
All SSZ containers implement merkleization according to the SSZ specification.
"""

from abc import ABC, abstractmethod
from typing import List, Tuple, Any


class SSZContainer(ABC):
    """
    Abstract base class for SSZ containers.

    All SSZ containers must implement the merkle_root method
    to calculate their SSZ merkle root according to the specification.
    """

    @abstractmethod
    def merkle_root(self) -> bytes:
        """
        Calculate the SSZ merkle root for this container.

        Returns:
            32-byte merkle root
        """
        pass

    @abstractmethod
    def get_fields(self) -> List[Tuple[str, str]]:
        """
        Get the field definitions for this container.

        Returns:
            List of (field_name, field_type) tuples
        """
        pass

    def __post_init__(self):
        """Called after dataclass initialization to perform validation."""
        self._validate_fields()

    def _validate_fields(self):
        """Validate that all required fields are present and correctly typed."""
        fields = self.get_fields()
        for field_name, field_type in fields:
            if not hasattr(self, field_name):
                raise ValueError(f"Missing required field: {field_name}")

    def to_dict(self) -> dict:
        """
        Convert container to dictionary representation.

        Returns:
            Dictionary with field names as keys
        """
        result = {}
        for field_name, _ in self.get_fields():
            value = getattr(self, field_name)
            if isinstance(value, SSZContainer):
                result[field_name] = value.to_dict()
            elif (
                isinstance(value, list) and value and isinstance(value[0], SSZContainer)
            ):
                result[field_name] = [item.to_dict() for item in value]
            else:
                result[field_name] = value
        return result

    def get_field_value(self, field_name: str) -> Any:
        """
        Get the value of a specific field.

        Args:
            field_name: Name of the field to retrieve

        Returns:
            Field value

        Raises:
            AttributeError: If field doesn't exist
        """
        return getattr(self, field_name)

    def set_field_value(self, field_name: str, value: Any) -> None:
        """
        Set the value of a specific field.

        Args:
            field_name: Name of the field to set
            value: New value for the field

        Raises:
            AttributeError: If field doesn't exist
        """
        setattr(self, field_name, value)
