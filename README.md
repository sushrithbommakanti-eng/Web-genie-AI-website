# Web Genie - AI Website Builder

An intelligent web application that generates complete websites based on user descriptions using AI technology.

## Features

- AI-powered website generation
- User authentication with email verification
- Secure payment integration with Razorpay
- Customizable templates
- Community feed for sharing generated websites
- Feedback system
- Subscription management
- Free trial system

## Tech Stack

- Python/Flask
- SQLite/MongoDB
- HTML/CSS/JavaScript
- OpenRouter API for AI generation
- Razorpay for payments
- SMTP for email verification

## Setup Instructions

1. Clone the repository:
```bash
git clone https://github.com/BHUKYA-DEVA/Web-genie-AI-website-major.git
cd Web-genie-AI-website-major
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Configure environment variables:
Create a `.env` file with the following variables:
```
EMAIL=your_email@gmail.com
PASSWORD=your_app_password
HOST=smtp.gmail.com
PORT=587
RAZORPAY_KEY_ID=your_razorpay_key
RAZORPAY_KEY_SECRET=your_razorpay_secret
```

5. Run the application:
```bash
python app.py
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 