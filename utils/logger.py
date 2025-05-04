import os
import sys
import warnings
import logging

# Apply aggressive warning suppression immediately on import
# This prevents warnings from appearing even during module initialization
def _suppress_warnings_immediately():
    """Suppress warnings immediately on module import"""
    # Suppress TensorFlow warnings - set this as early as possible
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # 0=Debug, 1=Info, 2=Warning, 3=Error
    
    # Suppress CUDA warnings
    os.environ['CUDA_VISIBLE_DEVICES'] = ''  # Disable GPU if not needed
    
    # Suppress cuDNN and cuBLAS warnings
    os.environ['TF_FORCE_GPU_ALLOW_GROWTH'] = 'true'
    
    # Disable verbose TensorFlow logging even before import
    os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
    os.environ['TF_CPP_MIN_VLOG_LEVEL'] = '3'
    os.environ['TF_ENABLE_DEPRECATION_WARNINGS'] = 'false'
    os.environ['TF_SILENT_ERRORS'] = '1'
    
    # Suppress tokenizer parallelism warnings
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    
    # Suppress Python warnings
    warnings.filterwarnings("ignore")
    
    # Temporarily redirect stderr to null device during this crucial import phase
    # This prevents any warnings that might occur when logger.py is imported
    original_stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')
    # After warning suppression setup, restore stderr
    sys.stderr = original_stderr

# Execute warning suppression immediately on module import
_suppress_warnings_immediately()

def configure_logging():
    """Configure logging and suppress unnecessary warnings to keep output clean"""
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
        
        # Disable computation placer warnings
        from tensorflow.python.util import module_wrapper as wrap
        wrap._PER_MODULE_WARNING_LIMIT = 0
    except ImportError:
        pass
        
    # Disable PyTorch warnings
    try:
        import torch
        torch.set_warn_always(False)
    except ImportError:
        pass