import streamlit as st
import json
import os
import hashlib
import secrets
import time
from datetime import datetime
import base64
from PIL import Image
import io

# Configure Streamlit page
st.set_page_config(
    page_title="Label-It - Indian Language Object Labeling",
    page_icon="🏷️",
    initial_sidebar_state="collapsed",
    layout="wide",
)

# Custom CSS for Indian language support and styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    .main-header {
        background: linear-gradient(135deg, #f97316 0%, #14b8a6 100%);
        padding: 2rem;
        border-radius: 1rem;
        color: white;
        text-align: center;
        margin-bottom: 2rem;
    }
    
    .language-text {
        font-family: 'Noto Sans Devanagari', 'Noto Sans Tamil', 'Noto Sans Telugu', sans-serif;
        font-size: 1.2rem;
        font-weight: 500;
    }
    
    .upload-section {
        background: #f8fafc;
        padding: 2rem;
        border-radius: 1rem;
        border: 2px dashed #e2e8f0;
        text-align: center;
        margin: 1rem 0;
    }
    
    .contribution-card {
        background: white;
        padding: 1.5rem;
        border-radius: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
        margin: 1rem 0;
        border-left: 4px solid #f97316;
    }
    
    .stats-container {
        display: flex;
        gap: 1rem;
        margin: 1rem 0;
    }
    
    .stat-card {
        background: linear-gradient(135deg, #64748b 0%, #475569 100%);
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
        flex: 1;
    }
</style>
""", unsafe_allow_html=True)

# Language translations
LANGUAGES = {
    'en': {
        'title': 'Label-It',
        'subtitle': 'Building AI-Ready Datasets for India\'s Linguistic Heritage',
        'upload_title': 'Upload & Label Object',
        'object_title': 'Object Title',
        'description': 'Description',
        'native_label': 'Native Language Label',
        'category': 'Category',
        'user_name': 'Your Name',
        'user_email': 'Your Email',
        'language': 'Language',
        'submit': 'Submit Contribution',
        'my_contributions': 'My Contributions',
        'total_objects': 'Total Objects',
        'languages_used': 'Languages Used',
        'verified': 'Verified',
        'pending': 'Pending Review'
    },
    'hi': {
        'title': 'Label-It',
        'subtitle': 'भारत की भाषाई विरासत के लिए AI-तैयार डेटासेट बनाना',
        'upload_title': 'वस्तु अपलोड और लेबल करें',
        'object_title': 'वस्तु का शीर्षक',
        'description': 'विवरण',
        'native_label': 'मूल भाषा लेबल',
        'category': 'श्रेणी',
        'user_name': 'आपका नाम',
        'user_email': 'आपका ईमेल',
        'language': 'भाषा',
        'submit': 'योगदान जमा करें',
        'my_contributions': 'मेरे योगदान',
        'total_objects': 'कुल वस्तुएं',
        'languages_used': 'उपयोग की गई भाषाएं',
        'verified': 'सत्यापित',
        'pending': 'समीक्षा लंबित'
    },
    'ta': {
        'title': 'Label-It',
        'subtitle': 'இந்தியாவின் மொழியியல் பாரம்பரியத்திற்கான AI-தயார் தரவுத்தளங்களை உருவாக்குதல்',
        'upload_title': 'பொருளைப் பதிவேற்றி லேபிளிடுங்கள்',
        'object_title': 'பொருளின் தலைப்பு',
        'description': 'விளக்கம்',
        'native_label': 'தாய்மொழி லேபிள்',
        'category': 'வகை',
        'user_name': 'உங்கள் பெயர்',
        'user_email': 'உங்கள் மின்னஞ்சல்',
        'language': 'மொழி',
        'submit': 'பங்களிப்பை சமர்ப்பிக்கவும்',
        'my_contributions': 'என் பங்களிப்புகள்',
        'total_objects': 'மொத்த பொருட்கள்',
        'languages_used': 'பயன்படுத்தப்பட்ட மொழிகள்',
        'verified': 'சரிபார்க்கப்பட்டது',
        'pending': 'மதிப்பாய்வு நிலுவையில்'
    }
}

CATEGORIES = [
    'Electronics', 'Furniture', 'Clothing', 'Kitchen Items', 'Tools', 
    'Books', 'Toys', 'Plants', 'Vehicles', 'Food Items'
]

INDIAN_LANGUAGES = [
    'Hindi', 'Tamil', 'Telugu', 'Bengali', 'Gujarati', 
    'Kannada', 'Malayalam', 'Marathi', 'Punjabi', 'Odia'
]

# Security functions
def hash_password(password: str, salt: str = None) -> tuple:
    """Hash password with salt"""
    if salt is None:
        salt = secrets.token_hex(16)
    
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt.encode('utf-8'),
        100000
    )
    return password_hash.hex(), salt

def verify_password(password: str, hashed: str, salt: str) -> bool:
    """Verify password against hash"""
    password_hash, _ = hash_password(password, salt)
    return password_hash == hashed

def generate_user_id() -> str:
    """Generate unique user ID"""
    return f"user_{int(time.time())}_{secrets.token_hex(8)}"

def validate_email(email: str) -> bool:
    """Basic email validation"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_phone(phone: str) -> bool:
    """Validate Indian phone number"""
    import re
    pattern = r'^[6-9]\d{9}$'
    return re.match(pattern, phone.replace(' ', '').replace('-', '')) is not None

def generate_otp() -> str:
    """Generate 6-digit OTP"""
    return f"{secrets.randbelow(900000) + 100000:06d}"

def is_rate_limited(user_id: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
    """Check if user is rate limited"""
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = {}
    
    now = time.time()
    attempts = st.session_state.login_attempts.get(user_id, [])
    
    # Remove old attempts outside the window
    recent_attempts = [t for t in attempts if now - t < window_minutes * 60]
    st.session_state.login_attempts[user_id] = recent_attempts
    
    return len(recent_attempts) >= max_attempts

def record_login_attempt(user_id: str):
    """Record a login attempt"""
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = {}
    
    if user_id not in st.session_state.login_attempts:
        st.session_state.login_attempts[user_id] = []
    
    st.session_state.login_attempts[user_id].append(time.time())

# Authentication functions
def create_user(name: str, email: str, password: str, phone: str = "", language: str = "Hindi") -> dict:
    """Create new user account"""
    if 'users' not in st.session_state:
        st.session_state.users = {}
    
    # Check if user already exists
    if email in st.session_state.users:
        return None
    
    # Hash password
    password_hash, salt = hash_password(password)
    
    user = {
        'id': generate_user_id(),
        'name': name,
        'email': email,
        'phone': phone,
        'password_hash': password_hash,
        'salt': salt,
        'preferred_language': language,
        'created_at': datetime.now().isoformat(),
        'is_verified': False,
        'last_login': None
    }
    
    st.session_state.users[email] = user
    return user

def authenticate_user(email: str, password: str) -> dict:
    """Authenticate user with email and password"""
    if 'users' not in st.session_state:
        st.session_state.users = {}
    
    user = st.session_state.users.get(email)
    if not user:
        return None
    
    if verify_password(password, user['password_hash'], user['salt']):
        user['last_login'] = datetime.now().isoformat()
        return user
    
    return None

def login_user(user: dict):
    """Log in user and create session"""
    st.session_state.current_user = user
    st.session_state.is_authenticated = True
    st.session_state.session_token = secrets.token_hex(32)

def logout_user():
    """Log out user and clear session"""
    if 'current_user' in st.session_state:
        del st.session_state.current_user
    if 'is_authenticated' in st.session_state:
        del st.session_state.is_authenticated
    if 'session_token' in st.session_state:
        del st.session_state.session_token

def is_authenticated() -> bool:
    """Check if user is authenticated"""
    return st.session_state.get('is_authenticated', False) and 'current_user' in st.session_state

def get_current_user() -> dict:
    """Get current authenticated user"""
    return st.session_state.get('current_user')

# Initialize session state
if 'contributions' not in st.session_state:
    st.session_state.contributions = []
if 'user_data' not in st.session_state:
    st.session_state.user_data = {}
if 'current_language' not in st.session_state:
    st.session_state.current_language = 'en'
if 'is_authenticated' not in st.session_state:
    st.session_state.is_authenticated = False
if 'show_login' not in st.session_state:
    st.session_state.show_login = True
if 'users' not in st.session_state:
    st.session_state.users = {}

def get_text(key):
    """Get translated text based on current language"""
    return LANGUAGES[st.session_state.current_language].get(key, key)

def save_contribution(data):
    """Save contribution to session state"""
    contribution = {
        'id': len(st.session_state.contributions) + 1,
        'user_id': get_current_user()['id'] if is_authenticated() else None,
        'timestamp': datetime.now().isoformat(),
        'status': 'pending',
        **data
    }
    st.session_state.contributions.append(contribution)
    return contribution

def login_page():
    """Secure login and registration page"""
    st.markdown(f"""
    <div class="main-header">
        <h1>🔐 {get_text('title')} - Secure Login</h1>
        <p style="font-size: 1.2rem; margin: 0;">Secure authentication required to contribute</p>
    </div>
    """, unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["🔑 Login", "📝 Sign Up"])
    
    with tab1:
        st.subheader("Login to Your Account")
        
        with st.form("login_form"):
            email = st.text_input("Email Address", placeholder="your@email.com")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            col1, col2 = st.columns([1, 1])
            with col1:
                login_submitted = st.form_submit_button("🔑 Login", type="primary", use_container_width=True)
            with col2:
                forgot_password = st.form_submit_button("🔄 Forgot Password", use_container_width=True)
            
            if login_submitted:
                if not email or not password:
                    st.error("Please enter both email and password")
                elif not validate_email(email):
                    st.error("Please enter a valid email address")
                elif is_rate_limited(email):
                    st.error("Too many login attempts. Please try again in 15 minutes.")
                else:
                    record_login_attempt(email)
                    user = authenticate_user(email, password)
                    
                    if user:
                        login_user(user)
                        st.success(f"Welcome back, {user['name']}!")
                        st.rerun()
                    else:
                        st.error("Invalid email or password")
            
            if forgot_password:
                st.info("Password reset functionality would be implemented here")
    
    with tab2:
        st.subheader("Create New Account")
        
        with st.form("signup_form"):
            col1, col2 = st.columns(2)
            
            with col1:
                name = st.text_input("Full Name", placeholder="Your full name")
                email = st.text_input("Email Address", placeholder="your@email.com")
                phone = st.text_input("Phone Number (Optional)", placeholder="10-digit number")
            
            with col2:
                password = st.text_input("Password", type="password", placeholder="Create strong password")
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Confirm your password")
                language = st.selectbox("Preferred Language", INDIAN_LANGUAGES)
            
            # Password strength indicator
            if password:
                strength_score = 0
                if len(password) >= 8:
                    strength_score += 1
                if any(c.isupper() for c in password):
                    strength_score += 1
                if any(c.islower() for c in password):
                    strength_score += 1
                if any(c.isdigit() for c in password):
                    strength_score += 1
                if any(c in "!@#$%^&*(),.?\":{}|<>" for c in password):
                    strength_score += 1
                
                strength_colors = ["🔴", "🟠", "🟡", "🟢", "💚"]
                strength_labels = ["Very Weak", "Weak", "Fair", "Good", "Strong"]
                
                if strength_score > 0:
                    st.write(f"Password Strength: {strength_colors[strength_score-1]} {strength_labels[strength_score-1]}")
            
            accept_terms = st.checkbox("I agree to the Terms of Service and Privacy Policy")
            
            signup_submitted = st.form_submit_button("📝 Create Account", type="primary", use_container_width=True)
            
            if signup_submitted:
                errors = []
                
                if not name or not email or not password or not confirm_password:
                    errors.append("Please fill in all required fields")
                if not validate_email(email):
                    errors.append("Please enter a valid email address")
                if phone and not validate_phone(phone):
                    errors.append("Please enter a valid 10-digit phone number")
                if len(password) < 8:
                    errors.append("Password must be at least 8 characters long")
                if password != confirm_password:
                    errors.append("Passwords do not match")
                if not accept_terms:
                    errors.append("Please accept the terms and conditions")
                if email in st.session_state.users:
                    errors.append("An account with this email already exists")
                
                if errors:
                    for error in errors:
                        st.error(error)
                else:
                    user = create_user(name, email, password, phone, language)
                    if user:
                        login_user(user)
                        st.success(f"Account created successfully! Welcome, {name}!")
                        st.balloons()
                        st.rerun()
                    else:
                        st.error("Failed to create account. Please try again.")
    
    # Security notice
    st.markdown("""
    ---
    ### 🔒 Security Notice
    - Your password is encrypted and securely stored
    - We use industry-standard security practices
    - Your data is protected and never shared
    - Rate limiting prevents brute force attacks
    """)

def main():
    # Check authentication
    if not is_authenticated():
        login_page()
        return
    
    current_user = get_current_user()
    
    # Language selector in sidebar
    with st.sidebar:
        st.title("🌍 Language / भाषा / மொழி")
        
        # User info
        st.markdown("---")
        st.markdown(f"**👤 {current_user['name']}**")
        st.markdown(f"📧 {current_user['email']}")
        
        if st.button("🚪 Logout", use_container_width=True):
            logout_user()
            st.rerun()
        
        st.markdown("---")
    
    language_options = {
        'en': '🇺🇸 English',
        'hi': '🇮🇳 हिन्दी',
        'ta': '🇮🇳 தமிழ்'
    }
    
    selected_lang = st.selectbox(
        "Select Language",
        options=list(language_options.keys()),
        format_func=lambda x: language_options[x],
        index=list(language_options.keys()).index(st.session_state.current_language)
    )
    
    if selected_lang != st.session_state.current_language:
        st.session_state.current_language = selected_lang
        st.rerun()

    # Main header
    st.markdown(f"""
    <div class="main-header">
        <h1>🏷️ {get_text('title')} - Welcome {current_user['name']}</h1>
        <p style="font-size: 1.2rem; margin: 0;">{get_text('subtitle')}</p>
    </div>
    """, unsafe_allow_html=True)

    # Navigation tabs
    tab1, tab2, tab3 = st.tabs([
        f"📤 {get_text('upload_title')}", 
        f"📊 My Contributions", 
        "🏆 Community"
    ])

    with tab1:
        upload_section()
    
    with tab2:
        my_contributions_section()
    
    with tab3:
        community_section()

def upload_section():
    """Upload and labeling section"""
    if not is_authenticated():
        st.error("Please log in to upload objects")
        return
    
    current_user = get_current_user()
    st.header(f"📤 {get_text('upload_title')}")
    
    # Image upload
    uploaded_files = st.file_uploader(
        "Choose images", 
        type=['png', 'jpg', 'jpeg'], 
        accept_multiple_files=True,
        help="Upload one or more images of objects to label"
    )
    
    if uploaded_files:
        # Display uploaded images
        cols = st.columns(min(len(uploaded_files), 3))
        for idx, uploaded_file in enumerate(uploaded_files):
            with cols[idx % 3]:
                image = Image.open(uploaded_file)
                st.image(image, caption=uploaded_file.name, use_column_width=True)
    
    # Form for object details
    with st.form("object_form"):
        col1, col2 = st.columns(2)
        
        with col1:
            title = st.text_input(get_text('object_title'), placeholder="e.g., Traditional Clay Pot")
            description = st.text_area(get_text('description'), placeholder="Describe the object and its use...")
            category = st.selectbox(get_text('category'), CATEGORIES)
        
        with col2:
            native_label = st.text_input(
                get_text('native_label'), 
                placeholder="Enter label in your native language",
                help="Use your native script (Devanagari, Tamil, Telugu, etc.)"
            )
            language = st.selectbox(get_text('language'), INDIAN_LANGUAGES)
            
            # Cultural context
            cultural_context = st.text_area(
                "Cultural Context (Optional)", 
                placeholder="Describe cultural or regional significance..."
            )
        
        # User details
        st.subheader("👤 User Details (Auto-filled)")
        col3, col4 = st.columns(2)
        
        with col3:
            user_name = st.text_input(get_text('user_name'), value=current_user['name'], disabled=True)
        with col4:
            user_email = st.text_input(get_text('user_email'), value=current_user['email'], disabled=True)
        
        # Submit button
        submitted = st.form_submit_button(
            get_text('submit'), 
            type="primary",
            use_container_width=True
        )
        
        if submitted:
            if title and native_label:
                # Save contribution
                contribution_data = {
                    'title': title,
                    'description': description,
                    'category': category,
                    'native_label': native_label,
                    'language': language,
                    'cultural_context': cultural_context,
                    'user_name': current_user['name'],
                    'user_email': current_user['email'],
                    'images': len(uploaded_files) if uploaded_files else 0
                }
                
                contribution = save_contribution(contribution_data)
                st.success(f"✅ Contribution submitted successfully! ID: {contribution['id']}")
                st.balloons()
            else:
                st.error("Please fill in all required fields (Title, Native Label)")

def my_contributions_section():
    """Display user's contributions"""
    st.header(f"📊 My Contributions")
    
    if not is_authenticated():
        st.error("Please log in to view your contributions")
        return
    
    current_user = get_current_user()
    
    # Filter contributions by current user
    user_contributions = [
        c for c in st.session_state.contributions 
        if c.get('user_id') == current_user['id']
    ]
    
    if not user_contributions:
        st.info("You haven't made any contributions yet. Upload your first object to get started!")
        return
    
    # Statistics
    total_objects = len(user_contributions)
    languages_used = len(set(c['language'] for c in user_contributions))
    verified_count = len([c for c in user_contributions if c['status'] == 'verified'])
    
    # Stats cards
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(get_text('total_objects'), total_objects)
    with col2:
        st.metric(get_text('languages_used'), languages_used)
    with col3:
        st.metric(get_text('verified'), verified_count)
    with col4:
        st.metric(get_text('pending'), total_objects - verified_count)
    
    # Contributions list
    st.subheader("Your Recent Contributions")
    
    for contribution in reversed(user_contributions[-10:]):  # Show last 10
        with st.container():
            col1, col2, col3 = st.columns([3, 2, 1])
            
            with col1:
                st.write(f"**{contribution['title']}**")
                st.write(f"🏷️ {contribution['native_label']} ({contribution['language']})")
                if contribution.get('description'):
                    st.caption(contribution['description'][:100] + "..." if len(contribution['description']) > 100 else contribution['description'])
            
            with col2:
                st.write(f"📂 {contribution['category']}")
                st.write(f"📅 {datetime.fromisoformat(contribution['timestamp']).strftime('%Y-%m-%d %H:%M')}")
            
            with col3:
                status_color = "🟢" if contribution['status'] == 'verified' else "🟡"
                status_text = get_text('verified') if contribution['status'] == 'verified' else get_text('pending')
                st.write(f"{status_color} {status_text}")
        
        st.divider()

def community_section():
    """Community features and statistics"""
    st.header("🏆 Community Dashboard")
    
    # Overall statistics
    total_contributions = len(st.session_state.contributions)
    unique_languages = len(set(c['language'] for c in st.session_state.contributions))
    unique_contributors = len(set(c['user_email'] for c in st.session_state.contributions))
    
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.metric("Total Contributions", total_contributions)
    with col2:
        st.metric("Languages Covered", unique_languages)
    with col3:
        st.metric("Active Contributors", unique_contributors)
    
    if st.session_state.contributions:
        st.subheader("Recent Community Contributions")
        
        # Display recent contributions from all users
        for contribution in reversed(st.session_state.contributions[-5:]):
            with st.container():
                col1, col2 = st.columns([3, 1])
                
                with col1:
                    st.write(f"**{contribution['title']}** by {contribution['user_name']}")
                    st.write(f"🏷️ {contribution['native_label']} ({contribution['language']})")
                    st.caption(f"📂 {contribution['category']}")
                
                with col2:
                    status_color = "🟢" if contribution['status'] == 'verified' else "🟡"
                    st.write(f"{status_color} {contribution['status'].title()}")
                    st.caption(datetime.fromisoformat(contribution['timestamp']).strftime('%Y-%m-%d'))
            
            st.divider()
    else:
        st.info("No contributions yet. Be the first to contribute!")

if __name__ == "__main__":
    main()