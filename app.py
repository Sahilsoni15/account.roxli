from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from functools import wraps
import firebase_admin
from firebase_admin import credentials, db
import hashlib
import os
import secrets
import jwt
from datetime import datetime, timedelta
import pytz
import uuid
from PIL import Image, ImageDraw, ImageFont
import io
import base64
import requests
import pyotp
import qrcode
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
CORS(app, supports_credentials=True, origins=['https://auth.roxli.in', 'https://account.roxli.in', 'https://mail.roxli.in'])

# Security headers
@app.after_request
def security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://auth.roxli.in https://account.roxli.in https://mail.roxli.in"
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

# JWT Configuration - Use same secret as main Roxli system
JWT_SECRET = 'roxli_jwt_secret_key_2024'
TOKEN_EXPIRY = timedelta(days=60)

# Rate limiting
rate_limits = {}

def rate_limit(max_requests=10, window=300):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            client_ip = request.remote_addr
            now = datetime.now().timestamp()
            
            if client_ip not in rate_limits:
                rate_limits[client_ip] = []
            
            rate_limits[client_ip] = [req_time for req_time in rate_limits[client_ip] if now - req_time < window]
            
            if len(rate_limits[client_ip]) >= max_requests:
                return jsonify({'error': 'Too many requests'}), 429
            
            rate_limits[client_ip].append(now)
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Firebase initialization
try:
    firebase_config = os.environ.get('FIREBASE_CONFIG')
    if firebase_config:
        import json
        cred = credentials.Certificate(json.loads(firebase_config))
        firebase_admin.initialize_app(cred, {
            'databaseURL': 'https://roxli-5aebd-default-rtdb.firebaseio.com/'
        })
        print("Firebase initialized successfully")
    else:
        # Try local file for development
        try:
            cred = credentials.Certificate('../Roxli/firebase-key.json')
            firebase_admin.initialize_app(cred, {
                'databaseURL': 'https://roxli-5aebd-default-rtdb.firebaseio.com/'
            })
            print("Firebase initialized with local file")
        except:
            print("No Firebase config found - service will not work properly")
except Exception as e:
    print(f"Firebase initialization failed: {e}")
    print("Service will not work properly without Firebase")
    # Create a reference to avoid import errors
    from firebase_admin import db

def generate_avatar(first_name, last_name):
    """Generate avatar like ui-avatars.com with solid background and white text"""
    initials = f"{first_name[0].upper()}{last_name[0].upper()}"
    
    # Solid background colors (similar to ui-avatars.com)
    colors = [
        '#2ecc71',  # Green
        '#3498db',  # Blue
        '#9b59b6',  # Purple
        '#e74c3c',  # Red
        '#f39c12',  # Orange
        '#1abc9c',  # Turquoise
        '#34495e',  # Dark Blue
        '#e67e22',  # Carrot
        '#95a5a6',  # Silver
        '#f1c40f',  # Yellow
    ]
    
    # Select color based on initials
    color_index = (ord(first_name[0]) + ord(last_name[0])) % len(colors)
    bg_color = colors[color_index]
    
    # Create square image (like ui-avatars.com)
    from PIL import Image, ImageDraw, ImageFont
    import io
    import base64
    
    size = (200, 200)
    img = Image.new('RGB', size, color=bg_color)
    draw = ImageDraw.Draw(img)
    
    # Try to load a clean font
    font_size = 80
    font = None
    
    font_paths = [
        "/System/Library/Fonts/Helvetica.ttc",  # macOS
        "C:/Windows/Fonts/arial.ttf",  # Windows
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux
    ]
    
    for font_path in font_paths:
        try:
            font = ImageFont.truetype(font_path, font_size)
            break
        except:
            continue
    
    if not font:
        try:
            font = ImageFont.load_default()
        except:
            font = None
    
    if font:
        # Calculate text position for centering
        bbox = draw.textbbox((0, 0), initials, font=font)
        text_width = bbox[2] - bbox[0]
        text_height = bbox[3] - bbox[1]
        x = (size[0] - text_width) // 2
        y = (size[1] - text_height) // 2
        
        # Draw white text (like ui-avatars.com)
        draw.text((x, y), initials, fill='#FFFFFF', font=font)
    
    # Convert to base64
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    # Return data URL
    return f"data:image/png;base64,{img_str}"

def verify_token(token):
    """Verify JWT token"""
    try:
        # Manual verification since jwt.decode is failing
        import hmac
        import hashlib
        import base64
        import json
        import time
        
        parts = token.split('.')
        if len(parts) != 3:
            return None
            
        header_encoded, payload_encoded, signature_encoded = parts
        
        # Verify signature
        message = f"{header_encoded}.{payload_encoded}"
        expected_signature = hmac.new(JWT_SECRET.encode(), message.encode(), hashlib.sha256).digest()
        expected_signature_encoded = base64.urlsafe_b64encode(expected_signature).decode().rstrip('=')
        
        if signature_encoded != expected_signature_encoded:
            print("DEBUG: Signature mismatch")
            return None
            
        # Decode payload
        payload_padded = payload_encoded + '=' * (4 - len(payload_encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_padded))
        
        # Check expiration
        if payload.get('exp', 0) < time.time():
            print("DEBUG: Token expired")
            return None
            
        # Token verified successfully
        return payload
        
    except Exception as e:
        print(f"DEBUG: Manual verification error: {e}")
        return None

def get_current_user():
    """Get current user from token or session"""
    # Try to get token from cookie first
    token = request.cookies.get('roxli_token')
    # Check for authentication token
    
    if token:
        payload = verify_token(token)
        # Token payload verified
        if payload:
            try:
                user_ref = db.reference(f'users/{payload["user_id"]}')
                user_data = user_ref.get()
            except Exception as e:
                print(f"Firebase error: {e}")
                return None
            if user_data:
                # Set session for future requests
                session['user_id'] = payload['user_id']
                session['email'] = user_data['email']
                # User authenticated successfully
                return {
                    'id': payload['user_id'],
                    'firstName': user_data.get('firstName', ''),
                    'lastName': user_data.get('lastName', ''),
                    'email': user_data['email'],
                    'avatar': user_data.get('avatar', ''),
                    'birthday': user_data.get('birthday', ''),
                    'gender': user_data.get('gender', ''),
                    'phone': user_data.get('phone', ''),
                    'homeAddress': user_data.get('homeAddress', ''),
                    'workAddress': user_data.get('workAddress', ''),
                    'otherAddress': user_data.get('otherAddress', ''),
                    'recoveryEmail': user_data.get('recovery_email', ''),
                    'recoveryPhone': user_data.get('recovery_phone', ''),
                    'twofaEnabled': user_data.get('twofa_enabled', False),
                    'createdAt': user_data.get('createdAt'),
                    'lastLogin': user_data.get('lastLogin')
                }
    
    # Fallback to session if no token
    if 'user_id' in session:
        # Using session authentication
        try:
            user_ref = db.reference(f'users/{session["user_id"]}')
            user_data = user_ref.get()
        except Exception as e:
            print(f"Firebase error: {e}")
            return None
        if user_data:
            return {
                'id': session['user_id'],
                'firstName': user_data.get('firstName', ''),
                'lastName': user_data.get('lastName', ''),
                'email': user_data['email'],
                'avatar': user_data.get('avatar', ''),
                'birthday': user_data.get('birthday', ''),
                'gender': user_data.get('gender', ''),
                'phone': user_data.get('phone', ''),
                'homeAddress': user_data.get('homeAddress', ''),
                'workAddress': user_data.get('workAddress', ''),
                'otherAddress': user_data.get('otherAddress', ''),
                'recoveryEmail': user_data.get('recovery_email', ''),
                'recoveryPhone': user_data.get('recovery_phone', ''),
                'twofaEnabled': user_data.get('twofa_enabled', False),
                'createdAt': user_data.get('createdAt'),
                'lastLogin': user_data.get('lastLogin')
            }
    
    # No authentication found
    return None

@app.route('/')
def dashboard():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_required'))
    return render_template('dashboard.html', user=user)

@app.route('/login-required')
def login_required():
    return render_template('login-required.html')

@app.route('/profile')
def profile():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_required'))
    return render_template('profile.html', user=user)

@app.route('/security')
def security():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_required'))
    return render_template('security.html', user=user)

@app.route('/devices')
def devices():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_required'))
    return render_template('devices.html', user=user)

@app.route('/apps')
def apps():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_required'))
    return render_template('apps.html', user=user)

@app.route('/privacy')
def privacy():
    user = get_current_user()
    if not user:
        return redirect(url_for('login_required'))
    return render_template('privacy.html', user=user)

@app.route('/api/update-profile', methods=['POST'])
def update_profile():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    updates = {}
    
    if 'firstName' in data:
        updates['firstName'] = data['firstName']
    if 'lastName' in data:
        updates['lastName'] = data['lastName']
    if 'avatar' in data:
        updates['avatar'] = data['avatar']
    if 'birthday' in data:
        updates['birthday'] = data['birthday']
    if 'gender' in data:
        updates['gender'] = data['gender']
    if 'phone' in data:
        updates['phone'] = data['phone']
    if 'homeAddress' in data:
        updates['homeAddress'] = data['homeAddress']
    if 'workAddress' in data:
        updates['workAddress'] = data['workAddress']
    if 'otherAddress' in data:
        updates['otherAddress'] = data['otherAddress']
    
    # Generate new avatar if name changed and no custom avatar provided
    if ('firstName' in updates or 'lastName' in updates) and not updates.get('avatar'):
        first_name = updates.get('firstName', user['firstName'])
        last_name = updates.get('lastName', user['lastName'])
        updates['avatar'] = generate_avatar(first_name, last_name)
    
    updates['updatedAt'] = datetime.now().isoformat()
    
    try:
        user_ref = db.reference(f'users/{user["id"]}')
        user_ref.update(updates)
        
        # Synchronize avatar across all services if avatar was updated
        if 'avatar' in updates or 'firstName' in updates or 'lastName' in updates:
            sync_avatar_across_services(user['id'], updates.get('avatar', user.get('avatar', '')), user['email'])
        
        return jsonify({'success': True, 'message': 'Profile updated successfully', 'updates': updates})
    except Exception as e:
        print(f"Profile update error: {e}")
        return jsonify({'error': 'Failed to update profile'}), 500

def sync_avatar_across_services(user_id, avatar_url, email):
    """Synchronize avatar across all Roxli services"""
    try:
        # Update in auth service database
        try:
            auth_user_ref = db.reference(f'users/{user_id}')
            auth_user_ref.update({'avatar': avatar_url})
            print(f"Avatar synced to auth service for user {user_id}")
        except Exception as e:
            print(f"Failed to sync avatar to auth service: {e}")
        
        # Notify other services about avatar update
        services = [
            'https://auth.roxli.in/api/sync-avatar',
            'https://mail.roxli.in/api/sync-avatar'
        ]
        
        for service_url in services:
            try:
                import requests
                response = requests.post(service_url, 
                                       json={
                                           'user_id': user_id,
                                           'avatar': avatar_url,
                                           'email': email
                                       }, 
                                       timeout=5)
                if response.status_code == 200:
                    print(f"Avatar synced to {service_url}")
                else:
                    print(f"Failed to sync avatar to {service_url}: {response.status_code}")
            except Exception as e:
                print(f"Error syncing avatar to {service_url}: {e}")
                
    except Exception as e:
        print(f"Error in avatar synchronization: {e}")

@app.route('/api/change-password', methods=['POST'])
@rate_limit(max_requests=3, window=300)
def change_password():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    
    # Validate password strength
    if len(new_password) < 8 or not any(c.isdigit() for c in new_password) or not any(c.isupper() for c in new_password):
        return jsonify({'error': 'Password must be 8+ chars with number and uppercase'}), 400
    
    # Verify current password
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    # Check if user has salt (new format) or not (old format)
    if user_data.get('salt'):
        current_hash = hashlib.sha256((current_password + user_data['salt']).encode()).hexdigest()
    else:
        current_hash = hashlib.sha256(current_password.encode()).hexdigest()
    
    if user_data['password'] != current_hash:
        return jsonify({'error': 'Current password is incorrect'}), 400
    
    # Update password with salt
    salt = secrets.token_hex(16)
    new_hash = hashlib.sha256((new_password + salt).encode()).hexdigest()
    user_ref.update({
        'password': new_hash,
        'salt': salt,
        'passwordChangedAt': datetime.now().isoformat()
    })
    
    return jsonify({'success': True, 'message': 'Password changed successfully'})

@app.route('/api/login-devices')
def get_login_devices():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get login sessions from Firebase
    sessions_ref = db.reference(f'user_sessions/{user["id"]}')
    sessions = sessions_ref.get() or {}
    
    # Get current session info
    user_agent = request.headers.get('User-Agent', '')
    current_ip = request.remote_addr
    
    devices = []
    current_session_id = request.cookies.get('session_id', 'current')
    
    # Add current device if no sessions exist
    if not sessions:
        device_type = 'mobile' if 'Mobile' in user_agent else 'desktop'
        browser = 'Chrome' if 'Chrome' in user_agent else 'Safari' if 'Safari' in user_agent else 'Firefox' if 'Firefox' in user_agent else 'Unknown'
        
        devices.append({
            'id': 'current',
            'deviceName': f'{browser} on {"Mobile" if device_type == "mobile" else "Desktop"}',
            'deviceType': device_type,
            'browser': browser,
            'location': f'IP: {current_ip}',
            'lastActive': datetime.now().isoformat(),
            'current': True
        })
    else:
        for session_id, session_data in sessions.items():
            is_current = session_id == current_session_id
            devices.append({
                'id': session_id,
                'deviceName': session_data.get('deviceName', 'Unknown Device'),
                'deviceType': session_data.get('deviceType', 'desktop'),
                'browser': session_data.get('browser', 'Unknown Browser'),
                'location': session_data.get('location', 'Unknown Location'),
                'lastActive': session_data.get('lastActive'),
                'current': is_current
            })
    
    return jsonify({'devices': devices})

@app.route('/api/logout-device', methods=['POST'])
@rate_limit(max_requests=5, window=300)
def logout_device():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    device_id = data.get('deviceId')
    password = data.get('password')
    
    # Verify password
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data['password'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 400
    
    # Remove device session
    if device_id != 'current':
        session_ref = db.reference(f'user_sessions/{user["id"]}/{device_id}')
        session_ref.delete()
        return jsonify({'success': True, 'message': 'Device logged out successfully'})
    else:
        return jsonify({'error': 'Cannot logout current device'}), 400

@app.route('/api/connected-apps')
def get_connected_apps():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get connected apps from Firebase
    apps_ref = db.reference(f'user_apps/{user["id"]}')
    apps = apps_ref.get() or {}
    
    connected_apps = []
    
    # Always include Roxli Account as connected app
    connected_apps.append({
        'id': 'roxli-account',
        'name': 'Roxli Account',
        'description': 'Manage your Roxli account settings and security',
        'permissions': ['Profile access', 'Security settings', 'Device management'],
        'connectedAt': user.get('createdAt', datetime.now().isoformat()),
        'lastUsed': datetime.now().isoformat(),
        'icon': 'fas fa-user-cog',
        'removable': False
    })
    
    # Add sample third-party apps for demonstration
    if not apps:
        sample_apps = [
            {
                'id': 'spotify-music',
                'name': 'Spotify',
                'description': 'Music streaming service',
                'permissions': ['Profile info', 'Email address'],
                'connectedAt': (datetime.now() - timedelta(days=45)).isoformat(),
                'lastUsed': (datetime.now() - timedelta(hours=3)).isoformat(),
                'icon': 'fab fa-spotify',
                'removable': True
            },
            {
                'id': 'github-dev',
                'name': 'GitHub',
                'description': 'Code repository and collaboration',
                'permissions': ['Profile info', 'Email address', 'Public repositories'],
                'connectedAt': (datetime.now() - timedelta(days=20)).isoformat(),
                'lastUsed': (datetime.now() - timedelta(days=1)).isoformat(),
                'icon': 'fab fa-github',
                'removable': True
            },
            {
                'id': 'discord-chat',
                'name': 'Discord',
                'description': 'Voice and text chat for communities',
                'permissions': ['Profile info', 'Email address'],
                'connectedAt': (datetime.now() - timedelta(days=10)).isoformat(),
                'lastUsed': (datetime.now() - timedelta(hours=12)).isoformat(),
                'icon': 'fab fa-discord',
                'removable': True
            },
            {
                'id': 'notion-workspace',
                'name': 'Notion',
                'description': 'All-in-one workspace for notes and docs',
                'permissions': ['Profile info', 'Email address', 'Workspace access'],
                'connectedAt': (datetime.now() - timedelta(days=5)).isoformat(),
                'lastUsed': (datetime.now() - timedelta(hours=8)).isoformat(),
                'icon': 'fas fa-sticky-note',
                'removable': True
            }
        ]
        
        # Store sample apps in Firebase
        for app in sample_apps:
            apps_ref.child(app['id']).set({
                'name': app['name'],
                'description': app['description'],
                'permissions': app['permissions'],
                'connectedAt': app['connectedAt'],
                'lastUsed': app['lastUsed'],
                'icon': app['icon'],
                'removable': app['removable']
            })
        
        connected_apps.extend(sample_apps)
    else:
        for app_id, app_data in apps.items():
            connected_apps.append({
                'id': app_id,
                'name': app_data.get('name'),
                'description': app_data.get('description'),
                'permissions': app_data.get('permissions', []),
                'connectedAt': app_data.get('connectedAt'),
                'lastUsed': app_data.get('lastUsed'),
                'icon': app_data.get('icon', 'fas fa-cube'),
                'removable': app_data.get('removable', True)
            })
    
    return jsonify({'apps': connected_apps})

@app.route('/api/revoke-app', methods=['POST'])
def revoke_app():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    app_id = data.get('appId')
    password = data.get('password')
    
    # Check if app is removable
    if app_id == 'roxli-account':
        return jsonify({'error': 'Cannot remove Roxli Account access'}), 400
    
    # Verify password
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data['password'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 400
    
    # Remove app access
    app_ref = db.reference(f'user_apps/{user["id"]}/{app_id}')
    app_ref.delete()
    
    return jsonify({'success': True, 'message': 'App access revoked successfully'})

@app.route('/api/user')
def get_user():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    return jsonify({'user': user})

@app.route('/api/auth-check')
def auth_check():
    """Check authentication status and redirect if needed"""
    user = get_current_user()
    if user:
        return jsonify({'authenticated': True, 'user': user})
    else:
        return jsonify({'authenticated': False}), 401

@app.route('/test-token')
def test_token():
    """Test token verification"""
    token = request.cookies.get('roxli_token')
    if token:
        # Try to decode manually to see what's wrong
        try:
            import base64
            import json
            parts = token.split('.')
            if len(parts) == 3:
                # Decode header and payload
                header_padded = parts[0] + '=' * (4 - len(parts[0]) % 4)
                payload_padded = parts[1] + '=' * (4 - len(parts[1]) % 4)
                
                header = json.loads(base64.urlsafe_b64decode(header_padded))
                payload_raw = json.loads(base64.urlsafe_b64decode(payload_padded))
                
                verified_payload = verify_token(token)
                
                return jsonify({
                    'token_present': True, 
                    'header': header,
                    'payload_raw': payload_raw,
                    'verified_payload': verified_payload,
                    'jwt_secret': JWT_SECRET
                })
        except Exception as e:
            return jsonify({'error': str(e)})
    return jsonify({'token_present': False})

@app.route('/api/set-token', methods=['POST'])
def set_token():
    """Set authentication token from popup"""
    data = request.json
    token = data.get('token')
    
    if not token:
        return jsonify({'error': 'Token required'}), 400
    
    # Try to verify with auth system first
    try:
        response = requests.post('https://auth.roxli.in/api/verify', 
                               json={'token': token}, 
                               timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('valid'):
                user = data['user']
                
                session['user_id'] = user['id']
                session['email'] = user['email']
                
                # Store logged account in localStorage via response
                resp = jsonify({
                    'success': True, 
                    'user': user,
                    'storeAccount': True,
                    'accountEmail': user['email']
                })
                resp.set_cookie('roxli_token', token, httponly=False, secure=False, samesite='Lax', path='/')
                return resp
    except Exception as e:
        print(f"Auth verification failed: {e}")
    
    # Fallback to local verification
    payload = verify_token(token)
    if payload:
        try:
            # Get user data from Firebase
            user_ref = db.reference(f'users/{payload["user_id"]}')
            user_data = user_ref.get()
        except Exception as e:
            print(f"Firebase error in set_token: {e}")
            return jsonify({'error': 'Database unavailable'}), 503
        
        if user_data:
            # Set session
            session['user_id'] = payload['user_id']
            session['email'] = user_data['email']
            
            user = {
                'id': payload['user_id'],
                'firstName': user_data.get('firstName', 'User'),
                'lastName': user_data.get('lastName', ''),
                'email': user_data['email'],
                'avatar': user_data.get('avatar', '')
            }
            
            resp = jsonify({'success': True, 'user': user})
            resp.set_cookie('roxli_token', token, httponly=False, secure=False, samesite='Lax', path='/')
            return resp
    
    return jsonify({'error': 'Invalid token'}), 401

@app.route('/api/available-accounts')
def get_available_accounts():
    """Get logged-in accounts for account switching"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Get accounts from request (sent from frontend localStorage)
    logged_in_emails = request.args.getlist('emails')
    
    # Always include current user with proper avatar
    current_user_account = {
        'id': user['id'],
        'firstName': user.get('firstName', 'User'),
        'lastName': user.get('lastName', ''),
        'email': user.get('email', ''),
        'avatar': user.get('avatar', '')
    }
    
    # Generate avatar if missing
    if not current_user_account['avatar'] or current_user_account['avatar'] == '':
        current_user_account['avatar'] = generate_avatar(
            current_user_account['firstName'], 
            current_user_account['lastName']
        )
    
    accounts = [current_user_account]
    
    if logged_in_emails:
        try:
            # Call auth service to get account data
            import requests
            auth_url = f"https://auth.roxli.in/api/available-accounts?{('&'.join([f'emails={email}' for email in logged_in_emails]))}"
            response = requests.get(auth_url, timeout=5)
            
            if response.status_code == 200:
                auth_data = response.json()
                for account in auth_data.get('accounts', []):
                    if account.get('email') != user['email']:
                        # Generate avatar if missing
                        if not account.get('avatar'):
                            avatar_name = f"{account.get('firstName', 'User')}+{account.get('lastName', '')}"
                            account['avatar'] = f"https://ui-avatars.com/api/?name={avatar_name}&background=random&color=fff&size=200&bold=true"
                        accounts.append(account)
        except Exception as e:
            print(f"Auth service error in available-accounts: {e}")
            pass
    
    # Sort accounts by email
    accounts.sort(key=lambda x: x.get('email', ''))
    
    return jsonify({
        'accounts': accounts,
        'currentUser': current_user_account
    })

@app.route('/api/switch-account', methods=['POST'])
def switch_account():
    """Switch to a different account"""
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email required'}), 400
    
    try:
        # Call auth service to switch account
        import requests
        response = requests.post('https://auth.roxli.in/api/switch-account', 
                               json={'email': email}, 
                               timeout=5,
                               cookies=request.cookies)
        
        if response.status_code == 200:
            auth_data = response.json()
            if auth_data.get('success'):
                # Use the token from auth service
                resp = jsonify(auth_data)
                resp.set_cookie('roxli_token', auth_data['token'], httponly=False, secure=False, samesite='Lax', path='/')
                return resp
        
        return jsonify({'error': 'Switch failed'}), 400
    except Exception as e:
        print(f"Auth service error in switch-account: {e}")
        return jsonify({'error': 'Account switching unavailable'}), 500


@app.route('/api/logout', methods=['POST'])
def logout():
    """Logout current user"""
    session.clear()
    response = jsonify({'success': True})
    response.set_cookie('roxli_token', '', expires=0, path='/')
    response.set_cookie('roxli_token', '', expires=0, domain='localhost')
    return response

@app.route('/api/logout-all-devices', methods=['POST'])
def logout_all_devices():
    """Logout from all devices"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Clear all sessions for this user
    sessions_ref = db.reference(f'user_sessions/{user["id"]}')
    sessions_ref.delete()
    
    return jsonify({'success': True, 'message': 'Logged out from all devices'})

# 2FA Endpoints
@app.route('/api/setup-2fa', methods=['POST'])
@rate_limit(max_requests=3, window=300)
def setup_2fa():
    """Setup 2FA for user"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Generate secret key
    secret = pyotp.random_base32()
    
    # Create TOTP object
    totp = pyotp.TOTP(secret)
    
    # Generate QR code
    provisioning_uri = totp.provisioning_uri(
        name=user['email'],
        issuer_name="Roxli Account"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffer = BytesIO()
    img.save(buffer, format='PNG')
    qr_code = base64.b64encode(buffer.getvalue()).decode()
    
    # Store secret temporarily (not activated yet)
    user_ref = db.reference(f'users/{user["id"]}')
    user_ref.update({
        'twofa_secret_temp': secret,
        'twofa_setup_time': datetime.now().isoformat()
    })
    
    return jsonify({
        'success': True,
        'secret': secret,
        'qr_code': f"data:image/png;base64,{qr_code}",
        'manual_entry_key': secret
    })

@app.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    """Verify 2FA code and activate"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    code = data.get('code')
    
    # Get temporary secret
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    temp_secret = user_data.get('twofa_secret_temp')
    
    if not temp_secret:
        return jsonify({'error': 'No 2FA setup in progress'}), 400
    
    # Verify code
    totp = pyotp.TOTP(temp_secret)
    if totp.verify(code):
        # Activate 2FA
        user_ref.update({
            'twofa_secret': temp_secret,
            'twofa_enabled': True,
            'twofa_activated_at': datetime.now().isoformat(),
            'twofa_secret_temp': None
        })
        return jsonify({'success': True, 'message': '2FA enabled successfully'})
    else:
        return jsonify({'error': 'Invalid code'}), 400

@app.route('/api/disable-2fa', methods=['POST'])
def disable_2fa():
    """Disable 2FA"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    password = data.get('password')
    
    # Verify password
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data['password'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 400
    
    # Disable 2FA
    user_ref.update({
        'twofa_enabled': False,
        'twofa_secret': None,
        'twofa_disabled_at': datetime.now().isoformat()
    })
    
    return jsonify({'success': True, 'message': '2FA disabled successfully'})

@app.route('/api/get-2fa-status')
def get_2fa_status():
    """Get 2FA status for user"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    return jsonify({
        'enabled': user_data.get('twofa_enabled', False),
        'setup_in_progress': bool(user_data.get('twofa_secret_temp'))
    })

# Recovery Email Endpoints
@app.route('/api/add-recovery-email', methods=['POST'])
def add_recovery_email():
    """Add recovery email"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    recovery_email = data.get('email')
    password = data.get('password')
    
    # Verify password
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data['password'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 400
    
    # Generate verification code
    verification_code = secrets.token_hex(3).upper()
    
    # Store recovery email temporarily
    user_ref.update({
        'recovery_email_temp': recovery_email,
        'recovery_email_code': verification_code,
        'recovery_email_code_time': datetime.now().isoformat()
    })
    
    # Send verification email (mock for now)
    try:
        send_verification_email(recovery_email, verification_code)
        return jsonify({
            'success': True, 
            'message': f'Verification code sent to {recovery_email}',
            'code': verification_code  # Remove in production
        })
    except Exception as e:
        return jsonify({'error': 'Failed to send verification email'}), 500

@app.route('/api/verify-recovery-email', methods=['POST'])
def verify_recovery_email():
    """Verify recovery email with code"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    code = data.get('code')
    
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    stored_code = user_data.get('recovery_email_code')
    temp_email = user_data.get('recovery_email_temp')
    
    if not stored_code or not temp_email:
        return jsonify({'error': 'No verification in progress'}), 400
    
    if code.upper() == stored_code:
        # Activate recovery email
        user_ref.update({
            'recovery_email': temp_email,
            'recovery_email_verified': True,
            'recovery_email_verified_at': datetime.now().isoformat(),
            'recovery_email_temp': None,
            'recovery_email_code': None
        })
        return jsonify({'success': True, 'message': 'Recovery email verified successfully'})
    else:
        return jsonify({'error': 'Invalid verification code'}), 400

@app.route('/api/remove-recovery-email', methods=['POST'])
def remove_recovery_email():
    """Remove recovery email"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    password = data.get('password')
    
    # Verify password
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data['password'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 400
    
    # Remove recovery email
    user_ref.update({
        'recovery_email': None,
        'recovery_email_verified': False,
        'recovery_email_removed_at': datetime.now().isoformat()
    })
    
    return jsonify({'success': True, 'message': 'Recovery email removed successfully'})

# Add new app connection endpoint
@app.route('/api/connect-app', methods=['POST'])
def connect_app():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    app_name = data.get('appName')
    app_description = data.get('appDescription', '')
    permissions = data.get('permissions', [])
    
    if not app_name:
        return jsonify({'error': 'App name is required'}), 400
    
    # Generate app ID
    app_id = f"app-{secrets.token_hex(8)}"
    
    # Store app connection
    apps_ref = db.reference(f'user_apps/{user["id"]}')
    apps_ref.child(app_id).set({
        'name': app_name,
        'description': app_description,
        'permissions': permissions,
        'connectedAt': datetime.now().isoformat(),
        'lastUsed': datetime.now().isoformat(),
        'icon': 'fas fa-cube',
        'removable': True
    })
    
    return jsonify({'success': True, 'message': f'{app_name} connected successfully', 'appId': app_id})

# Simulate popular app connections
@app.route('/api/simulate-app-connection', methods=['POST'])
def simulate_app_connection():
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    popular_apps = [
        {
            'name': 'Netflix',
            'description': 'Streaming entertainment service',
            'permissions': ['Profile info', 'Email address'],
            'icon': 'fas fa-play'
        },
        {
            'name': 'Instagram',
            'description': 'Photo and video sharing social network',
            'permissions': ['Profile info', 'Email address', 'Photo access'],
            'icon': 'fab fa-instagram'
        },
        {
            'name': 'LinkedIn',
            'description': 'Professional networking platform',
            'permissions': ['Profile info', 'Email address', 'Professional info'],
            'icon': 'fab fa-linkedin'
        },
        {
            'name': 'Figma',
            'description': 'Collaborative design tool',
            'permissions': ['Profile info', 'Email address', 'Design files'],
            'icon': 'fab fa-figma'
        }
    ]
    
    # Pick a random app to connect
    import random
    app_data = random.choice(popular_apps)
    app_id = f"{app_data['name'].lower()}-{secrets.token_hex(4)}"
    
    # Store app connection
    apps_ref = db.reference(f'user_apps/{user["id"]}')
    apps_ref.child(app_id).set({
        'name': app_data['name'],
        'description': app_data['description'],
        'permissions': app_data['permissions'],
        'connectedAt': datetime.now().isoformat(),
        'lastUsed': datetime.now().isoformat(),
        'icon': app_data['icon'],
        'removable': True
    })
    
    return jsonify({
        'success': True, 
        'message': f'{app_data["name"]} connected successfully!',
        'app': {
            'id': app_id,
            'name': app_data['name'],
            'description': app_data['description']
        }
    })

# Recovery Phone Endpoints
@app.route('/api/add-recovery-phone', methods=['POST'])
def add_recovery_phone():
    """Add recovery phone"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    phone = data.get('phone')
    password = data.get('password')
    
    # Verify password
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data['password'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 400
    
    # Generate verification code
    verification_code = str(secrets.randbelow(900000) + 100000)
    
    # Store recovery phone temporarily
    user_ref.update({
        'recovery_phone_temp': phone,
        'recovery_phone_code': verification_code,
        'recovery_phone_code_time': datetime.now().isoformat()
    })
    
    # Send SMS (mock for now)
    return jsonify({
        'success': True, 
        'message': f'Verification code sent to {phone}',
        'code': verification_code  # Remove in production
    })

@app.route('/api/verify-recovery-phone', methods=['POST'])
def verify_recovery_phone():
    """Verify recovery phone with code"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    code = data.get('code')
    
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    stored_code = user_data.get('recovery_phone_code')
    temp_phone = user_data.get('recovery_phone_temp')
    
    if not stored_code or not temp_phone:
        return jsonify({'error': 'No verification in progress'}), 400
    
    if code == stored_code:
        # Activate recovery phone
        user_ref.update({
            'recovery_phone': temp_phone,
            'recovery_phone_verified': True,
            'recovery_phone_verified_at': datetime.now().isoformat(),
            'recovery_phone_temp': None,
            'recovery_phone_code': None
        })
        return jsonify({'success': True, 'message': 'Recovery phone verified successfully'})
    else:
        return jsonify({'error': 'Invalid verification code'}), 400

@app.route('/api/remove-recovery-phone', methods=['POST'])
def remove_recovery_phone():
    """Remove recovery phone"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.json
    password = data.get('password')
    
    # Verify password
    user_ref = db.reference(f'users/{user["id"]}')
    user_data = user_ref.get()
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    if user_data['password'] != password_hash:
        return jsonify({'error': 'Password is incorrect'}), 400
    
    # Remove recovery phone
    user_ref.update({
        'recovery_phone': None,
        'recovery_phone_verified': False,
        'recovery_phone_removed_at': datetime.now().isoformat()
    })
    
    return jsonify({'success': True, 'message': 'Recovery phone removed successfully'})

def send_verification_email(email, code):
    """Send verification email (mock implementation)"""
    # In production, use actual SMTP server
    print(f"Sending verification code {code} to {email}")
    # Mock successful send
    return True

@app.route('/api/refresh-avatar', methods=['POST'])
def refresh_avatar():
    """Refresh user avatar if missing"""
    user = get_current_user()
    if not user:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Regenerate avatar using ui-avatars.com
    avatar_name = f"{user['firstName']}+{user['lastName']}"
    new_avatar = f"https://ui-avatars.com/api/?name={avatar_name}&background=667eea&color=fff&size=200&bold=true"
    
    # Update in Firebase
    user_ref = db.reference(f'users/{user["id"]}')
    user_ref.update({'avatar': new_avatar})
    
    # Sync across services
    sync_avatar_across_services(user['id'], new_avatar, user['email'])
    
    return jsonify({'success': True, 'avatar': new_avatar})

@app.route('/api/sync-avatar', methods=['POST'])
def sync_avatar():
    """Endpoint for other services to sync avatar updates"""
    data = request.json
    user_id = data.get('user_id')
    avatar_url = data.get('avatar')
    email = data.get('email')
    
    if not user_id or not avatar_url:
        return jsonify({'error': 'User ID and avatar URL required'}), 400
    
    try:
        # Update user avatar in local database
        user_ref = db.reference(f'users/{user_id}')
        user_ref.update({'avatar': avatar_url})
        
        return jsonify({'success': True, 'message': 'Avatar synced successfully'})
    except Exception as e:
        print(f"Error syncing avatar: {e}")
        return jsonify({'error': 'Failed to sync avatar'}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5003))
    app.run(debug=False, host='0.0.0.0', port=port)