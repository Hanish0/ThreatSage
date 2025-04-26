from transformers import pipeline

class IncidentResponder:
    def __init__(self):
        self.model = pipeline("text-generation", model='gpt2')

    def reason(self, log_details: dict) -> str:
        formatted_input = (
            "You are a cybersecurity expert.\n"
            "Given the following IP information, suggest an appropriate security action in 2-3 sentences.\n\n"
            f"IP Information:\n{log_details}\n\n"
            "Recommendation:"
        )

        response = self.model(formatted_input, max_length=200, num_return_sequences=1, truncation=True)

        # Extract only what comes after "Recommendation:"
        return response[0]['generated_text'].split('Recommendation:')[-1].strip()
