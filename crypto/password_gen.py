import string
import secrets
from typing import Dict, Optional
from ui.colors import Colors
from ui.display import gradient_print


def generate_password(
    length: int,
    use_uppercase: bool = True,
    use_lowercase: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True
) -> Optional[str]:
    try:
        if length <= 0:
            print(f"{Colors.RED}Length must be positive.{Colors.NC}")
            return None
        
        if length < 8:
            print(f"{Colors.YELLOW}Warning: Length less than 8 is generally not recommended.{Colors.NC}")
        
        character_set = ""
        if use_uppercase:
            character_set += string.ascii_uppercase
        if use_lowercase:
            character_set += string.ascii_lowercase
        if use_digits:
            character_set += string.digits
        if use_symbols:
            character_set += string.punctuation
        
        if not character_set:
            print(f"{Colors.RED}You must select at least one character set!{Colors.NC}")
            return None
        
        password = ''.join(secrets.choice(character_set) for _ in range(length))
        return password
    except Exception as e:
        print(f"{Colors.RED}Error generating password: {e}{Colors.NC}")
        return None


def check_password_strength(password: str) -> Dict[str, any]:
    if not password:
        return {
            'length': 0,
            'has_uppercase': False,
            'has_lowercase': False,
            'has_digits': False,
            'has_symbols': False,
            'strength': 'weak',
            'score': 0,
        }
    
    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(c in string.punctuation for c in password)
    
    score = 0
    score += len(password) * 2
    if has_uppercase:
        score += 10
    if has_lowercase:
        score += 10
    if has_digits:
        score += 10
    if has_symbols:
        score += 15
    
    if score < 30:
        strength = 'weak'
    elif score < 50:
        strength = 'medium'
    elif score < 70:
        strength = 'strong'
    else:
        strength = 'very_strong'
    
    return {
        'length': len(password),
        'has_uppercase': has_uppercase,
        'has_lowercase': has_lowercase,
        'has_digits': has_digits,
        'has_symbols': has_symbols,
        'strength': strength,
        'score': min(score, 100),
    }


def validate_password_requirements(
    password: str,
    min_length: int = 8,
    require_uppercase: bool = True,
    require_lowercase: bool = True,
    require_digits: bool = True,
    require_symbols: bool = False
) -> tuple[bool, list[str]]:
    errors = []
    
    if len(password) < min_length:
        errors.append(f"Password must be at least {min_length} characters long")
    
    if require_uppercase and not any(c.isupper() for c in password):
        errors.append("Password must contain at least one uppercase letter")
    
    if require_lowercase and not any(c.islower() for c in password):
        errors.append("Password must contain at least one lowercase letter")
    
    if require_digits and not any(c.isdigit() for c in password):
        errors.append("Password must contain at least one digit")
    
    if require_symbols and not any(c in string.punctuation for c in password):
        errors.append("Password must contain at least one symbol")
    
    return (len(errors) == 0, errors)


def show_password_strength(password: str) -> None:
    if not password:
        gradient_print("Password is empty.")
        return
    
    strength_data = check_password_strength(password)
    
    gradient_print(f"\n{'='*50}")
    gradient_print("Password Strength Analysis")
    gradient_print(f"{'='*50}")
    
    gradient_print(f"\nLength: {strength_data['length']} characters")
    
    gradient_print("\nCharacter Types:")
    check_mark = "✓"
    cross_mark = "✗"
    
    gradient_print(f"  Uppercase letters: {check_mark if strength_data['has_uppercase'] else cross_mark}")
    gradient_print(f"  Lowercase letters: {check_mark if strength_data['has_lowercase'] else cross_mark}")
    gradient_print(f"  Digits: {check_mark if strength_data['has_digits'] else cross_mark}")
    gradient_print(f"  Symbols: {check_mark if strength_data['has_symbols'] else cross_mark}")
    
    strength = strength_data['strength']
    if strength == 'very_strong':
        strength_text = "VERY STRONG"
    elif strength == 'strong':
        strength_text = "STRONG"
    elif strength == 'medium':
        strength_text = "MEDIUM"
    else:
        strength_text = "WEAK"
    
    gradient_print(f"\nStrength Level: {strength_text}")
    
    score = strength_data['score']
    bar_length = 30
    filled = int((score / 100) * bar_length)
    bar = '█' * filled + '░' * (bar_length - filled)
    gradient_print(f"Score: {bar} {score}/100")
    
    print(f"\n{Colors.CYAN}{'='*50}{Colors.NC}\n")
