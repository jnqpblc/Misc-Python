import argparse
import random
import calendar
from datetime import datetime, timedelta
import string

# Function to get the current and previous seasons based on the current month
def get_seasons():
    seasons = ["Winter", "Spring", "Summer", "Fall"]
    current_month = datetime.now().month
    # Get the current season index based on the current month
    current_season_index = (current_month % 12) // 3
    # Get the current and previous seasons
    return [seasons[(current_season_index - 1) % 4], seasons[current_season_index]]

# Function to get the previous, current, and next month names
def get_months():
    current_date = datetime.now()
    # Get the previous, current, and next months
    return [
        calendar.month_name[(current_date - timedelta(days=30)).month],  # Previous month
        calendar.month_name[current_date.month],                         # Current month
        calendar.month_name[(current_date + timedelta(days=30)).month],  # Next month
    ]

# Function to check if a password contains at least 3 of the 4 groups: uppercase, lowercase, number, symbol
def has_three_of_four_groups(password):
    groups = {
        "uppercase": any(c.isupper() for c in password),
        "lowercase": any(c.islower() for c in password),
        "number": any(c.isdigit() for c in password),
        "symbol": any(c in string.punctuation for c in password),
    }
    # Count how many groups are present
    return sum(groups.values()) >= 3

# Function to generate passwords using a seed list
def generate_passwords(seed_list, min_pwd_length=8, complex_check=True):
    password_list = []
    current_year_full = str(datetime.now().year)  # Get the full current year (e.g., 2024)
    current_year_short = current_year_full[2:]    # Get the last two digits of the year (e.g., 24)

    for seed in seed_list:
        # Add common variations and ensure 3 of 4 groups are present
        variations = [
            seed.lower(),
            seed.lower() + "1",
            seed.lower() + "!",
            seed.lower() + "123",
            seed.lower() + "123!",
            seed.lower() + current_year_short,
            seed.lower() + current_year_short + "!",
            seed.lower() + current_year_full,
            seed.lower() + current_year_full + "!",
            seed.capitalize(),
            seed.capitalize() + "1",
            seed.capitalize() + "!",
            seed.capitalize() + "123",
            seed.capitalize() + "123!",
            seed.capitalize() + current_year_short,
            seed.capitalize() + current_year_short + "!",
            seed.capitalize() + current_year_full,
            seed.capitalize() + current_year_full + "!",
        ]

        # If complexity check is enabled, only add passwords that meet the criteria
        if complex_check:
            password_list.extend([pwd for pwd in variations if len(pwd) >= min_pwd_length and has_three_of_four_groups(pwd)])
        else:
            password_list.extend([pwd for pwd in variations if len(pwd) >= min_pwd_length])

    return password_list

# Main function to handle input and generate the password list
def main(passwords=None, seeds=None, min_pwd_length=8, complex_check=True):
    password_list = []

    if passwords:
        # If passwords are provided, use them directly
        password_list = passwords
    elif seeds:
        # If seeds are provided, generate passwords using the seeds
        password_list = generate_passwords(seeds, min_pwd_length, complex_check)
    else:
        # If neither passwords nor seeds are provided, use seasons and months as seeds
        seasons = get_seasons()
        months = get_months()
        password_list = generate_passwords(seasons + months, min_pwd_length, complex_check)

    # Shuffle the generated password list
    random.shuffle(password_list)

    return password_list

# Function to parse arguments
def parse_arguments():
    parser = argparse.ArgumentParser(description="Generate a list of common weak passwords.")
    parser.add_argument('-s', "--seed", type=str, help="A CSV string of seeds (e.g. password,welcome) for password generation.")
    parser.add_argument('-m', "--min-length", type=int, default=8, help="Minimum password length (default: 8).")
    parser.add_argument('-c', "--complex-check", action="store_true", help="Enable complex check (requires at least 3 of 4: uppercase, lowercase, number, symbol).")
    
    return parser.parse_args()

# Example usage
if __name__ == "__main__":
    # Parse arguments
    args = parse_arguments()

    # Check if --seed was provided
    if args.seed:
        seeds = [seed.strip() for seed in args.seed.split(',')]  # Convert CSV string to list
        password_list = main(seeds=seeds, min_pwd_length=args.min_length, complex_check=args.complex_check)
    else:
        password_list = main(min_pwd_length=args.min_length, complex_check=args.complex_check)

    for password in password_list:
        print(password)
