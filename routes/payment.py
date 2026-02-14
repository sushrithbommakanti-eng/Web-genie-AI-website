from flask import Blueprint, jsonify, request, session, redirect, url_for
import razorpay
from config import RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET

payment_bp = Blueprint('payment', __name__)

# Initialize Razorpay client
client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))

@payment_bp.route('/create-order', methods=['POST'])
def create_order():
    try:
        data = request.get_json()
        plan = data.get('plan')
        
        # Define plan amounts in paise (1 INR = 100 paise)
        plan_amounts = {
            'basic': 90000,    # ₹900
            'pro': 190000,     # ₹1900
            'enterprise': 490000  # ₹4900
        }
        
        amount = plan_amounts.get(plan)
        if not amount:
            return jsonify({'error': 'Invalid plan selected'}), 400

        # Create Razorpay order
        order_data = {
            'amount': amount,
            'currency': 'INR',
            'payment_capture': 1,
            'notes': {
                'plan': plan
            }
        }
        
        order = client.order.create(data=order_data)
        
        return jsonify({
            'order_id': order['id'],
            'amount': order['amount'],
            'currency': order['currency']
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@payment_bp.route('/payment-success', methods=['POST'])
def payment_success():
    try:
        # Verify payment signature
        params_dict = {
            'razorpay_payment_id': request.form.get('razorpay_payment_id'),
            'razorpay_order_id': request.form.get('razorpay_order_id'),
            'razorpay_signature': request.form.get('razorpay_signature')
        }
        
        client.utility.verify_payment_signature(params_dict)
        
        # Payment successful - update user's subscription status
        # Add your logic here to update the user's subscription in the database
        
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@payment_bp.route('/payment-failure')
def payment_failure():
    return redirect(url_for('subscription', error='Payment failed. Please try again.')) 