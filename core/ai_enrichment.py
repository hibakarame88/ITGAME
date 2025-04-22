from openai import OpenAI
import pandas as pd

client = OpenAI(
    base_url="https://api.scaleway.ai/ac596d48-8004-4950-be23-dca49fca778f/v1",
    api_key="695f4799-c556-476c-9f04-25b7b192b4cd"
)

def enrich_with_ai(csv_path="data/summary.csv", output_path="data/enriched.txt"):
    df = pd.read_csv(csv_path)
    summary = df.groupby(["src_ip", "dst_ip", "proto"]).size().reset_index(name="count")
    prompt = "Analyse ce trafic réseau :\n" + summary.to_string(index=False)
    response = client.chat.completions.create(
        model="mistral-nemo-instruct-2407",
        messages=[
            {"role": "system", "content": "You are a helpful assistant"},
            {"role": "user", "content": prompt}
        ],
        max_tokens=300
    )
    content = response.choices[0].message.content
    with open(output_path, "w") as f:
        f.write(content)
    return content
