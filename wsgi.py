from app import app

# This is needed for Vercel
app.debug = False

if __name__ == "__main__":
    app.run()