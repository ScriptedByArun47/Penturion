from openai import OpenAI # This import will now work

client = OpenAI(
  api_key="your_api_key_here",  # Replace with your actual OpenAI API key
)
completion = client.chat.completions.create(
  model="gpt-4o-mini",
  # The 'store' parameter is not valid for client.chat.completions.create().
  # You'll need to handle storing the completion separately if desired.
  messages=[
    {"role": "user", "content": "write a haiku about ai"}
  ]
)

print(completion.choices[0].message)