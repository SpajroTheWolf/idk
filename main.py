@app.post("/register")
def register(data: LoginData):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == data.username).first()
        if user:
            raise HTTPException(status_code=400, detail="User exists")

        hashed = get_password_hash(data.password)
        api_key = generate_api_key()

        new_user = User(
            username=data.username,
            password=hashed,
            api_key=api_key
        )

        db.add(new_user)
        db.commit()

        return {
            "msg": "User created",
            "api_key": api_key   # 🔥 TO JEST TO CZEGO CHCESZ
        }

    finally:
        db.close()
