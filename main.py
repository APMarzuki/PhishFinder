# main.py

import os
from phishfinder.analyzer import PhishFinder


def main():
    """
    Loads the sample email file and initiates the PhishFinder analysis.
    """
    # Define the path to your sample email file
    sample_file_name = "sample_phish.eml"
    # Construct the full path to the file inside the 'data' directory
    sample_file_path = os.path.join("data", sample_file_name)

    print(f"--- Starting PhishFinder Analysis ---")

    try:
        # 1. Load the raw email content
        with open(sample_file_path, 'r', encoding='utf-8') as f:
            raw_email_content = f.read()

        print(f"✅ Successfully loaded raw email from: {sample_file_path}")

        # 2. Initialize and run the analyzer
        analyzer = PhishFinder(raw_email_content)
        analyzer.analyze_and_report()

    except FileNotFoundError:
        print(f"❌ Error: The sample file '{sample_file_name}' was not found in the 'data' folder.")
        print("ACTION: Please create a file named 'sample_phish.eml' inside the 'data' folder.")
    except Exception as e:
        print(f"❌ An unexpected error occurred during analysis: {e}")


if __name__ == "__main__":
    # Ensure ipwhois doesn't clutter the output during setup phase
    # This is a common practice when using libraries that can be verbose.
    import logging

    logging.getLogger('ipwhois').setLevel(logging.WARNING)

    main()