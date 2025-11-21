import os
import logging
from typing import Optional, Dict, Any, List
from dataclasses import dataclass

from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain_ollama import ChatOllama
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_openai import OpenAIEmbeddings
from langchain_core.embeddings import Embeddings
from enum import StrEnum

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

class LLMProviders(StrEnum):
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    OLLAMA = "ollama"

@dataclass
class ModelConfig:
    """Configuration for a specific model"""
    model_id: str
    provider: LLMProviders
    api_key_env: Optional[str] = None
    base_url_env: Optional[str] = None
    default_max_tokens: int = 4096
    context_window: int = 4096  # Total context window in tokens
    supports_tools: bool = True

# Define available models with their configurations
MODEL_CONFIGS = {
    # OpenAI models
    "gpt-4o": ModelConfig(
        "gpt-4o", 
        LLMProviders.OPENAI, 
        "OPENAI_API_KEY", 
        context_window=128000,
        default_max_tokens=16384
    ),
    "gpt-4o-mini": ModelConfig(
        "gpt-4o-mini", 
        LLMProviders.OPENAI, 
        "OPENAI_API_KEY",
        context_window=128000,
        default_max_tokens=16384
    ),
    "gpt-4-turbo": ModelConfig(
        "gpt-4-turbo", 
        LLMProviders.OPENAI, 
        "OPENAI_API_KEY",
        context_window=128000,
        default_max_tokens=4096
    ),
    "gpt-3.5-turbo": ModelConfig(
        "gpt-3.5-turbo", 
        LLMProviders.OPENAI, 
        "OPENAI_API_KEY",
        context_window=16385,
        default_max_tokens=4096
    ),
    
    # Anthropic models
    "claude-sonnet-4": ModelConfig(
        "claude-sonnet-4-20250514", 
        LLMProviders.ANTHROPIC, 
        "ANTHROPIC_API_KEY",
        context_window=200000,
        default_max_tokens=8192
    ),
    "claude-sonnet-4.5": ModelConfig(
        "claude-sonnet-4-5-20250929", 
        LLMProviders.ANTHROPIC, 
        "ANTHROPIC_API_KEY",
        context_window=200000,
        default_max_tokens=8192
    ),
    "claude-haiku-4.5": ModelConfig(
        "claude-haiku-4-5-20251001",
        LLMProviders.ANTHROPIC,
        "ANTHROPIC_API_KEY",
        context_window=200000,
        default_max_tokens=8192
    ),
    
    # Ollama models (no API key required)
    "llama3.1": ModelConfig(
        "llama3.1", 
        LLMProviders.OLLAMA,
        context_window=128000,
        default_max_tokens=4096
    ),
}

# Add embedding model configs
EMBEDDING_MODELS = {
    "text-embedding-3-large": {
        "provider": "openai",
        "api_key_env": "OPENAI_API_KEY",
    },
    "text-embedding-3-small": {
        "provider": "openai", 
        "api_key_env": "OPENAI_API_KEY",
    },
    # Add more embedding models as needed
}

# Define size categories with fallback chains
MODEL_SIZE_FALLBACKS = {
    "small": [
        "claude-haiku-4.5",
        "gpt-4o-mini", 
        "gpt-3.5-turbo",
        "llama3.1:8b",
        "qwen2.5"
    ],
    "medium": [
        "gpt-4o",
        "claude-3-5-sonnet-20241022",
        "gpt-4-turbo", 
        "llama3.1:70b",
        "llama3.1"
    ],
    "large": [
        "claude-3-opus-20240229",
        "gpt-4o",
        "claude-3-5-sonnet-20241022",
        "llama3.1:70b"
    ]
}

class ModelFactory:
    """Factory for creating and managing language models with fallbacks"""
    
    def __init__(self):
        self._model_cache: Dict[str, BaseChatModel] = {}
        self._available_models_cache: Dict[str, List[str]] = {}
    
    def _check_model_availability(self, model_name: str) -> bool:
        """Check if a model is available (has required API keys, etc.)"""
        if model_name not in MODEL_CONFIGS:
            return False
            
        config = MODEL_CONFIGS[model_name]
        
        # For Ollama, assume available (could ping the server in future)
        if config.provider == LLMProviders.OLLAMA:
            return True
            
        # Check if required API key is available
        if config.api_key_env and not os.getenv(config.api_key_env):
            return False
            
        return True
    
    def _check_embedding_model_availability(self, model_name: str) -> bool:
        """Check if an embedding model is available"""
        if model_name not in EMBEDDING_MODELS:
            return False
            
        config = EMBEDDING_MODELS[model_name]
        
        # Check if required API key is available
        if config.get("api_key_env") and not os.getenv(config["api_key_env"]):
            return False
            
        return True
    
    def get_embedding_model(self, model_name: str = "text-embedding-3-large") -> Embeddings:
        """
        Get an embedding model instance
        
        Args:
            model_name: Name of the embedding model
            
        Returns:
            An embedding model instance
            
        Raises:
            ValueError: If the model is unknown or unavailable
        """
        if model_name not in EMBEDDING_MODELS:
            raise ValueError(f"Unknown embedding model: {model_name}")
        
        config = EMBEDDING_MODELS[model_name]
        
        if not self._check_embedding_model_availability(model_name):
            raise ValueError(f"Embedding model {model_name} is not available. Is the {config.get('api_key_env')} set?")
        
        if config["provider"] == "openai":
            return OpenAIEmbeddings(model=model_name)
        
        # Add support for other providers here
        raise ValueError(f"Unsupported embedding model provider: {config['provider']}")

    
    def get_available_models(self, provider: Optional[LLMProviders] = None) -> List[str]:
        """Get list of available models based on current environment"""
        cache_key = provider.value if provider else "all"
        
        if cache_key not in self._available_models_cache:
            if provider:
                available = [
                    model for model, cfg in MODEL_CONFIGS.items() 
                    if cfg.provider == provider and self._check_model_availability(model)
                ]
            else:
                available = [
                    model for model in MODEL_CONFIGS.keys() 
                    if self._check_model_availability(model)
                ]
            
            if not available:
                provider_msg = f" for provider '{provider}'" if provider else ""
                raise RuntimeError(f"No available models found{provider_msg}. Please check your API key configurations.")
            
            self._available_models_cache[cache_key] = available
            logger.debug(f"Cached {len(available)} available models for provider: {cache_key}")
        
        return self._available_models_cache[cache_key]
    
    def _create_model(self, model_name: str, **kwargs) -> BaseChatModel:
        """Create a model instance"""
        if model_name not in MODEL_CONFIGS:
            raise ValueError(f"Unknown model: {model_name}")
            
        config = MODEL_CONFIGS[model_name]
        
        # Common parameters
        model_kwargs = {
            "temperature": kwargs.get("temperature", 0),
            **{k: v for k, v in kwargs.items() if k != "temperature"}
        }
        
        if config.provider == LLMProviders.OPENAI:
            return ChatOpenAI(
                model=config.model_id,
                api_key=os.getenv(config.api_key_env),
                max_tokens=kwargs.get("max_tokens", config.default_max_tokens),
                **model_kwargs
            )
        elif config.provider == LLMProviders.ANTHROPIC:
            return ChatAnthropic(
                model_name=config.model_id,
                api_key=os.getenv(config.api_key_env),
                **model_kwargs
            )
        elif config.provider == LLMProviders.OLLAMA:
            base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
            return ChatOllama(
                model=config.model_id,
                base_url=base_url,
                **model_kwargs
            )
        else:
            raise ValueError(f"Unsupported provider: {config.provider}")
    
    def get_model(self, 
                  model_name: str, 
                  use_fallbacks: bool = True,
                  cache: bool = True,
                  **kwargs) -> BaseChatModel:
        """
        Get a model instance with optional fallbacks
        
        Args:
            model_name: Specific model name or size category ("small", "medium", "large")
            use_fallbacks: Whether to try fallback models if primary fails
            cache: Whether to cache the model instance
            **kwargs: Additional parameters for the model
        """
        cache_key = f"{model_name}:{hash(frozenset(kwargs.items()))}"
        
        if cache and cache_key in self._model_cache:
            return self._model_cache[cache_key]
        
        # If it's a size category, get the fallback list
        if model_name in MODEL_SIZE_FALLBACKS:
            candidates = MODEL_SIZE_FALLBACKS[model_name]
        else:
            candidates = [model_name]
        
        # If not using fallbacks, only try the first candidate
        if not use_fallbacks:
            candidates = candidates[:1]
        
        available_models = self.get_available_models()
        
        for candidate in candidates:
            if candidate in available_models:
                try:
                    model = self._create_model(candidate, **kwargs)
                    logger.info(f"Successfully created model: {candidate}")
                    
                    if cache:
                        self._model_cache[cache_key] = model
                    
                    return model
                    
                except Exception as e:
                    logger.warning(f"Failed to create model {candidate}: {e}")
                    continue
        
        raise RuntimeError(
            f"No available models found for '{model_name}'. "
            f"Available models: {available_models}. "
            f"Tried: {candidates}"
        )
    
    def list_models_by_provider(self) -> Dict[str, List[str]]:
        """List available models grouped by provider"""
        available = self.get_available_models()
        by_provider = {}
        
        for model in available:
            provider = MODEL_CONFIGS[model].provider
            if provider not in by_provider:
                by_provider[provider] = []
            by_provider[provider].append(model)
        
        return by_provider

# Global factory instance
model_factory = ModelFactory()

def get_model(model_name: str, **kwargs) -> BaseChatModel:
    """
    Get a model instance with automatic fallbacks
    
    Args:
        model_name: Model name (e.g., "gpt-4o", "claude-3-5-sonnet-20241022") 
                   or size category ("small", "medium", "large")
        **kwargs: Additional model parameters (temperature, max_tokens, etc.)
    
    Returns:
        Configured model instance
        
    Examples:
        >>> model = get_model("gpt-4o", temperature=0.7)
        >>> model = get_model("medium", temperature=0.5, max_tokens=2048)
        >>> model = get_model("claude-3-5-sonnet-20241022")
    """
    return model_factory.get_model(model_name, **kwargs)


def get_max_tokens(model_name: str) -> int:
    """
    Get the maximum output token limit for a given model
    
    Args:
        model_name: Name of the model
        
    Returns:
        Maximum output token limit for the model
    """
    if model_name not in MODEL_CONFIGS:
        raise ValueError(f"Unknown model: {model_name}")
    
    return MODEL_CONFIGS[model_name].default_max_tokens


def get_context_window(model_name: str) -> int:
    """
    Get the total context window size (input + output) for a given model
    
    Args:
        model_name: Name of the model or size category
        
    Returns:
        Total context window size in tokens
        
    Examples:
        >>> get_context_window("gpt-4o")
        128000
        >>> get_context_window("claude-sonnet-4")
        200000
    """
    # If it's a size category, get the first available model
    if model_name in MODEL_SIZE_FALLBACKS:
        available_models = model_factory.get_available_models()
        for candidate in MODEL_SIZE_FALLBACKS[model_name]:
            if candidate in available_models and candidate in MODEL_CONFIGS:
                return MODEL_CONFIGS[candidate].context_window
        raise ValueError(f"No available models found for size category: {model_name}")
    
    if model_name not in MODEL_CONFIGS:
        raise ValueError(f"Unknown model: {model_name}")
    
    return MODEL_CONFIGS[model_name].context_window

def get_max_input_tokens(model_name: str) -> int:
    """
    Get the maximum input token limit for a given model
    Args:
        model_name: Name of the model
    Returns:
        Maximum input token limit for the model
    """
    if model_name not in MODEL_CONFIGS:
        raise ValueError(f"Unknown model: {model_name}")
    
    config = MODEL_CONFIGS[model_name]
    return config.context_window - config.default_max_tokens 
        

def get_embedding_model(model_name: str = "text-embedding-3-large") -> Embeddings:
    """
    Get an embedding model instance
    
    Args:
        model_name: Name of the embedding model
        
    Returns:
        An embedding model instance
    """
    return model_factory.get_embedding_model(model_name)

def get_available_models(provider: Optional[LLMProviders] = None) -> List[str]:
    """
    Get list of currently available models
    provider: Optional[LLMProviders] specifies filtering by provider
    
    """
    return model_factory.get_available_models(provider)

def list_models_by_provider() -> Dict[str, List[str]]:
    """List available models grouped by provider"""
    return model_factory.list_models_by_provider()

# Backward compatibility
def get_llm(size: str, **kwargs) -> BaseChatModel:
    """Legacy function for backward compatibility"""
    logger.warning("get_llm() is deprecated. Use get_model() instead.")
    return get_model(size, **kwargs)