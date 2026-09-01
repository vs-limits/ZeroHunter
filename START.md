# 后端
cd backend
pip install -r requirements.txt


# 前端
cd frontend
npm install



# 后端
cd backend
uvicorn app.server.app:app --host 127.0.0.1 --port 8000 --reload

# 前端
cd frontend
npm run dev

# 打开 http://localhost:5173
