import os
import warnings
import logging

def configure_logging():
    """Configure logging and suppress unnecessary warnings to keep output clean"""
    # Suppress TensorFlow warnings
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # 0=Debug, 1=Info, 2=Warning, 3=Error
    
    # Suppress tokenizer parallelism warnings
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    
    # Suppress Python warnings
    warnings.filterwarnings("ignore")
    
    # Configure logging for specific libraries
    for logger_name in ["transformers", "tensorflow", "torch", "urllib3", 
                       "numpy", "matplotlib", "requests", "huggingface_hub",
                       "accelerate", "PIL"]:
        logging.getLogger(logger_name).setLevel(logging.ERROR)

    # Disable all other logging except critical
    logging.basicConfig(level=logging.CRITICAL)
    
    # Force disable TF info/warnings via direct API
    try:
        import tensorflow as tf
        tf.get_logger().setLevel('ERROR')
        tf.autograph.set_verbosity(0)
    except ImportError:
        pass
        
    # Disable PyTorch warnings
    try:
        import torch
        torch.set_warn_always(False)
    except ImportError:
        pass