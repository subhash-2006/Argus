import os
from dotenv import load_dotenv
from google import genai
load_dotenv()
c = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))
for m in ["gemini-2.5-flash", "gemini-3.8-flash"]:
    try:
        print(m, "->", c.models.generate_content(model=m, contents="Reply OK").text)
    except Exception as e:
        print(m, "FAILED:", e)