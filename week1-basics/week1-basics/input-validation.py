# Demonstration of insecure vs secure input handling

user_input = input("Enter your age: ")

# Insecure
print("Insecure output:", user_input)

# Secure
if user_input.isdigit():
    print("Secure output:", int(user_input))
else:
    print("Invalid input detected")
