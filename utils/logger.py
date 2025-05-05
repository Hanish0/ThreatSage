import os
import sys
import warnings
import logging

def _suppress_warnings_immediately():
    """Suppress warnings immediately on module import"""
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # 0=Debug, 1=Info, 2=Warning, 3=Error
    os.environ['CUDA_VISIBLE_DEVICES'] = ''
    os.environ['TF_FORCE_GPU_ALLOW_GROWTH'] = 'true'
    os.environ['TF_ENABLE_ONEDNN_OPTS'] = '0'
    os.environ['TF_CPP_MIN_VLOG_LEVEL'] = '3'
    os.environ['TF_ENABLE_DEPRECATION_WARNINGS'] = 'false'
    os.environ['TF_SILENT_ERRORS'] = '1'
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    
    warnings.filterwarnings("ignore")
    
    original_stderr = sys.stderr
    sys.stderr = open(os.devnull, 'w')
    sys.stderr = original_stderr

_suppress_warnings_immediately()

def configure_logging():
    """Configure logging and suppress unnecessary warnings to keep output clean"""
    for logger_name in ["transformers", "tensorflow", "torch", "urllib3", 
                       "numpy", "matplotlib", "requests", "huggingface_hub",
                       "accelerate", "PIL"]:
        logging.getLogger(logger_name).setLevel(logging.ERROR)

    logging.basicConfig(level=logging.CRITICAL)
    
    try:
        import tensorflow as tf
        tf.get_logger().setLevel('ERROR')
        tf.autograph.set_verbosity(0)
        
        from tensorflow.python.util import module_wrapper as wrap
        wrap._PER_MODULE_WARNING_LIMIT = 0
    except ImportError:
        pass
        
    try:
        import torch
        torch.set_warn_always(False)
    except ImportError:
        pass