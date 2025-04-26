from transformers import pipeline

class IncidentResponder:
    def __init__(self):
        self.model = pipeline("text-generation", model='gpt2')

    def reason(self,log_details: dict) -> str:
        formatted_input = f"Log details: {log_details}\nWhat should be the recommended action?"
        response = self.model(formatted_input, max_length=200, num_return_sequences=1, truncation=True)

        return response[0]['generated_text']
    