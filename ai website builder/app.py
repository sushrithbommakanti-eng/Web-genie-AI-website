from flask import Flask, render_template, request, jsonify, send_file
import os
import requests
import json
import tempfile
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# OpenRouter Configuration
OPENROUTER_API_KEY = "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"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

def generate_website_content(prompt):
    """Generate website content using OpenRouter API"""
    try:
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:5000",
            "X-Title": "AI Website Builder"
        }
        
        data = {
            "model": "deepseek/deepseek-v3-base:free",
            "messages": [
                {"role": "system", "content": "You are a professional web developer. Generate a complete website based on the user's prompt. Return the response in JSON format with 'html' and 'css' keys."},
                {"role": "user", "content": f"Create a website with the following requirements: {prompt}. Include modern design, responsive layout, and necessary JavaScript. Return only the JSON with html and css."}
            ],
            "temperature": 0.7
        }
        
        print("Sending request to OpenRouter API...")  # Debug log
        response = requests.post(OPENROUTER_URL, headers=headers, json=data)
        print(f"Response status: {response.status_code}")  # Debug log
        
        if response.status_code != 200:
            print(f"Error response: {response.text}")  # Debug log
            raise Exception(f"API Error: {response.status_code} - {response.text}")
            
        response_data = response.json()
        print(f"Response data: {json.dumps(response_data, indent=2)}")  # Debug log
        
        # Check if we have a valid response structure
        if not isinstance(response_data, dict):
            raise Exception(f"Invalid response format: expected dict, got {type(response_data)}")
            
        # Try to get the content from different possible response structures
        content = None
        if 'choices' in response_data and response_data['choices']:
            content = response_data['choices'][0].get('message', {}).get('content')
        elif 'response' in response_data:
            content = response_data['response']
        elif 'content' in response_data:
            content = response_data['content']
            
        if not content:
            raise Exception(f"Could not find content in response: {json.dumps(response_data, indent=2)}")
            
        print("Successfully received content from API")  # Debug log
        
        # Extract JSON from the response
        try:
            website_data = json.loads(content)
            if not isinstance(website_data, dict):
                raise ValueError("Website data is not a dictionary")
                
            # Ensure we have both html and css
            if 'html' not in website_data or 'css' not in website_data:
                # If missing either html or css, create a basic structure
                return {
                    "html": website_data.get('html', '<div>No HTML content generated</div>'),
                    "css": website_data.get('css', 'body { font-family: Arial, sans-serif; margin: 20px; }')
                }
                
            return website_data
            
        except json.JSONDecodeError as e:
            print(f"JSON parsing error: {str(e)}")  # Debug log
            # If JSON parsing fails, create a basic structure with the raw content
            return {
                "html": f"<html><body><h1>Generated Website</h1><div>{content}</div></body></html>",
                "css": "body { font-family: Arial, sans-serif; margin: 20px; }"
            }
            
    except Exception as e:
        print(f"Error in generate_website_content: {str(e)}")  # Debug log
        return {
            "html": f"<html><body><h1>Error</h1><p>Failed to generate website: {str(e)}</p></body></html>",
            "css": "body { font-family: Arial, sans-serif; margin: 20px; color: red; }"
        }

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/generate", methods=["POST"])
def generate():
    prompt = request.json.get("prompt", "")
    if not prompt:
        return jsonify({"error": "No prompt provided"}), 400
    
    try:
        website_data = generate_website_content(prompt)
        return jsonify({
            "success": True,
            "html": website_data["html"],
            "css": website_data["css"]
        })
    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route("/download/<path:filename>")
def download_file(filename):
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)
