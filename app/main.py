from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import os
import subprocess
import json
from fastapi import HTTPException
from groq import Groq

app = FastAPI()

# Configure Groq
client = Groq(api_key="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")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def extract_metadata(file_path: str):
    try:
        result = subprocess.run(
            ["exiftool", "-json", file_path],
            capture_output=True,
            text=True,
            check=True,
        )
        metadata_list = json.loads(result.stdout)
        return metadata_list[0] if metadata_list else {}

    except FileNotFoundError:
        raise HTTPException(status_code=500, detail="ExifTool not found. Please install it.")
    except subprocess.CalledProcessError:
        raise HTTPException(status_code=500, detail="Error extracting metadata.")
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Invalid metadata format.")


@app.post("/upload/")
async def upload_file(file: UploadFile = File(...), email: str = Form(...)):
    try:
        file_path = f"./uploads/{file.filename}"
        with open(file_path, "wb") as buffer:
            buffer.write(await file.read())
        metadata = extract_metadata(file_path)
        
        os.remove(file_path)

        print("\n File uploaded successfully")
        return JSONResponse(
            content={"message": "File uploaded successfully", "metadata": metadata},
            status_code=200,
        )
    except Exception as e:
        print(f"\n Upload error: {str(e)}")
        raise HTTPException(status_code=500, detail="Upload failed")


@app.post("/recommend")
async def recommend(metadata: dict):
    try:
        if not metadata:
            print("\n Error: Empty metadata received")
            return JSONResponse(
                content={"error": "No metadata provided"},
                status_code=400
            )

        print("\n Received metadata:", json.dumps(metadata, indent=2))
        metadata_str = json.dumps(metadata, indent=2)

        prompt = f"""You are an AI expert in metadata forensics and anomaly detection. Your primary task is to analyze the metadata for potential anomalies and provide a comprehensive analysis.

Here's the metadata to analyze:
{metadata_str}

First, carefully check for these anomalies:
1. Suspicious timestamps (e.g., future dates, inconsistent modification times)
2. Missing critical metadata fields
3. Unusual software signatures or editing tools
4. Inconsistent file properties
5. Manipulation indicators
6. Hash mismatches
7. Invalid or unexpected values
8. Metadata field tampering

Return your analysis in this EXACT JSON format:
{{
    "anomaly_detected": true/false,  # Set to true if ANY anomaly is found
    "reason": "Detailed explanation of ALL anomalies found, or 'No anomalies detected' if none found",
    "recommendations": [  # List specific actions to address each anomaly
        "Action 1 to address anomaly",
        "Action 2 to address anomaly",
        ...
    ],
    "best_practices": [  # Only if no anomalies found
        "Security practice 1",
        "Security practice 2",
        ...
    ],
    "metadata_summary": {{
        "brief_summary": {{
            "title": "File Properties Overview",
            "content": ["Key file properties with focus on anomalous values"]
        }},
        "authenticity": {{
            "title": "Authenticity & Manipulation Analysis",
            "content": ["Detailed analysis of file authenticity and potential manipulation"]
        }},
        "metadata_table": {{
            "title": "Metadata Analysis Table",
            "headers": ["Field", "Value", "Status"],
            "rows": [
                ["field_name", "field_value", "normal/suspicious/anomalous"]
            ]
        }},
        "use_cases": {{
            "title": "Recommended Applications",
            "content": ["Specific use cases based on metadata analysis"]
        }}
    }}
}}

IMPORTANT:
1. Be STRICT about anomaly detection - if anything seems unusual, mark it as an anomaly
2. For each anomaly, explain WHY it's suspicious and what the expected value should be
3. Make recommendations specific to each detected anomaly
4. In the metadata table, mark each field as:
   - 'normal' - expected value
   - 'suspicious' - unusual but not definitely anomalous
   - 'anomalous' - definitely problematic
5. If you're unsure about a value, mark it as suspicious"""

        print("\n Sending prompt to Groq...")
        try:
            response = client.chat.completions.create(
                messages=[{"role": "user", "content": prompt}],
                model="mixtral-8x7b-32768",
                temperature=0.3,
                max_tokens=1000,
            )
            
            print("\n Received response from Groq")
            result = json.loads(response.choices[0].message.content)
            print("\n Parsed result:", json.dumps(result, indent=2))

            # Ensure all required fields exist with default values
            result = {
                "anomaly_detected": result.get("anomaly_detected", False),
                "reason": result.get("reason", "No issues detected."),
                "recommendations": result.get("recommendations", []),
                "best_practices": result.get("best_practices", []),
                "metadata_summary": result.get("metadata_summary", {
                    "brief_summary": {"title": "File Properties Overview", "content": []},
                    "authenticity": {"title": "Authenticity & Manipulation Analysis", "content": []},
                    "metadata_table": {
                        "title": "Metadata Analysis Table",
                        "headers": ["Field", "Value", "Status"],
                        "rows": []
                    },
                    "use_cases": {"title": "Recommended Applications", "content": []}
                })
            }

            print("\n Sending response to frontend")
            return JSONResponse(content=result, status_code=200)

        except Exception as groq_error:
            print(f"\n Groq API Error: {str(groq_error)}")
            return JSONResponse(
                content={"error": "Failed to analyze metadata"},
                status_code=500
            )

    except Exception as e:
        print(f"\n Server Error: {str(e)}")
        return JSONResponse(
            content={"error": str(e)},
            status_code=500
        )