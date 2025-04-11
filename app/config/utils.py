import re

class Utils:

    @staticmethod
    def lerp(x: int, x0: int, x1: int, y0: int, y1: int):
        """
        Linear Interpolation - Maps value from range [from_start, from_end] to [to_start, to_end]
        Args:
            x: Value to be mapped
            x0: Starting value of original range
            x1: Ending value of original range
            y0: Starting value of mapped range
            y1: Ending value of mapped range

        Returns: Value mapped between range [y0, y1]
        """
        return y0 + (x - x0) * (y1 - y0) / (x1 - x0)

    # Extract domain from sender
    @staticmethod
    def extract_sender_domain(email):
        match = re.search(r'@([A-Za-z0-9.-]+)', str(email))
        return match.group(1).lower() if match else 'unknown'

    # Clean and normalize text
    @staticmethod
    def clean_text(text):
        text = re.sub(r"http\S+", "", text)  # Remove URLs
        text = re.sub(r"[^a-zA-Z ]", " ", text)  # Remove special characters
        return text.lower()

    # Combine and clean features
    @staticmethod
    def prepare_text(row):
        sender_domain = Utils.extract_sender_domain(row['sender'])
        combined = f"{sender_domain} {row.get('subject', '')} {row.get('body', '')}"
        return Utils.clean_text(combined)


if __name__ == "__main__":
    print(Utils.lerp(4,0,5,0,30))
    print(Utils.extract_sender_domain("user@gmail.com"))
