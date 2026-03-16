fake_leaks = [
    "admin@example.com",
    "user123@gmail.com",
    "test@company.com"
]

def check_leak(email):

    if email in fake_leaks:
        return {"status":"leaked","risk":"HIGH"}
    
    return {"status":"safe","risk":"LOW"}