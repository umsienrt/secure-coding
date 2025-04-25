import sqlite3
import uuid
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from flask_socketio import SocketIO, send
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'
DATABASE = 'market.db'
socketio = SocketIO(app)

# 데이터베이스 연결 관리: 요청마다 연결 생성 후 사용, 종료 시 close
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # 결과를 dict처럼 사용하기 위함
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 테이블 생성 (최초 실행 시에만)
def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # 사용자 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                bio TEXT
            )
        """)
        # 상품 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS product (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                price TEXT NOT NULL,
                seller_id TEXT NOT NULL
            )
        """)
        # 신고 테이블 생성
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS report (
                id TEXT PRIMARY KEY,
                reporter_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                reason TEXT NOT NULL

            )
        """)
        db.commit()

# 기본 라우트
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# 회원가입
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        # 중복 사용자 체크
        cursor.execute("SELECT * FROM user WHERE username = ?", (username,))
        if cursor.fetchone() is not None:
            flash('이미 존재하는 사용자명입니다.')
            return redirect(url_for('register'))
        user_id = str(uuid.uuid4())
        cursor.execute("INSERT INTO user (id, username, password) VALUES (?, ?, ?)",
                       (user_id, username, password))
        db.commit()
        flash('회원가입이 완료되었습니다. 로그인 해주세요.')
        return redirect(url_for('login'))
    return render_template('register.html')

# 로그인
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        cursor.execute("SELECT * FROM user WHERE username = ? AND password=?", (username, password))
        user = cursor.fetchone()
        if user:
            session['user_id'] = user['id']
            flash('로그인 성공!')
            return redirect(url_for('dashboard'))
        else:
            flash('아이디 또는 비밀번호가 올바르지 않습니다.')
            return redirect(url_for('login'))
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('로그아웃되었습니다.')
    return redirect(url_for('index'))

# 대시보드: 사용자 정보와 전체 상품 리스트 표시
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    # 현재 사용자 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    # 전체 상품 조회 
    cursor.execute("SELECT * FROM product")
    all_products = cursor.fetchall()

    # 검색 키워드 처리
    search_query = request.args.get('q')
    search_results = []
    if search_query:
        cursor.execute(
            "SELECT * FROM product WHERE title LIKE ?",
            ('%' + search_query + '%',)
        )
        search_results = cursor.fetchall()

    return render_template(
        'dashboard.html',
        user=current_user,
        products=all_products,
        search_results=search_results,
        query=search_query
    )

# 프로필 페이지: bio 업데이트 가능
@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    db = get_db()
    cursor = db.cursor()

    cursor.execute("SELECT * FROM user WHERE id = ?", (session['user_id'],))
    current_user = cursor.fetchone()

    if request.method == 'POST':
        bio = request.form.get('bio', '')
        current_pw = request.form.get('current_password')
        new_pw = request.form.get('new_password')

        cursor.execute("UPDATE user SET bio = ? WHERE id = ?", (bio, session['user_id']))
        flash('소개글이 업데이트되었습니다.')

        if current_pw and new_pw:
            if current_user['password'] == current_pw:
                cursor.execute("UPDATE user SET password = ? WHERE id = ?", (new_pw, session['user_id']))
                flash('비밀번호가 변경되었습니다.')
            else:
                flash('현재 비밀번호가 일치하지 않습니다.')
        db.commit()
        return redirect(url_for('profile'))
    return render_template('profile.html', user=current_user)


# 상품 등록
@app.route('/product/new', methods=['GET', 'POST'])
def new_product():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        price = request.form['price']
        db = get_db()
        cursor = db.cursor()
        product_id = str(uuid.uuid4())
        cursor.execute(
            "INSERT INTO product (id, title, description, price, seller_id) VALUES (?, ?, ?, ?, ?)",
            (product_id, title, description, price, session['user_id'])
        )
        db.commit()
        flash('상품이 등록되었습니다.')
        return redirect(url_for('dashboard'))
    return render_template('new_product.html')

# 상품 상세보기
@app.route('/product/<product_id>')
def view_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))
    # 판매자 정보 조회
    cursor.execute("SELECT * FROM user WHERE id = ?", (product['seller_id'],))
    seller = cursor.fetchone()
    return render_template('view_product.html', product=product, seller=seller)

# 신고하기
@app.route('/report', methods=['GET', 'POST'])
def report():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        target_id = request.form['target_id']  
        reason = request.form['reason']  

        db = get_db()
        cursor = db.cursor()

        # 신고 ID 생성
        report_id = str(uuid.uuid4())

        # 신고 데이터를 DB에 삽입
        cursor.execute(
            "INSERT INTO report (id, reporter_id, target_id, reason) VALUES (?, ?, ?, ?)",
            (report_id, session['user_id'], target_id, reason)
        )
        db.commit()

        flash('신고가 접수되었습니다.')
        return redirect(url_for('dashboard'))

    return render_template('report.html')

# 실시간 채팅: 클라이언트가 메시지를 보내면 전체 브로드캐스트
@socketio.on('send_message')
def handle_send_message_event(data):
    data['message_id'] = str(uuid.uuid4())
    send(data, broadcast=True)

#관리자 페이지
@app.route('/admin')
def admin_page():
    db = get_db()
    cursor = db.cursor()

 # 모든 사용자 목록 조회
    cursor.execute("SELECT * FROM user")
    all_users = cursor.fetchall()

    cursor.execute("""
    SELECT
     report.id AS report_id,
    report.reporter_id,
    report.target_id,
    report.reason,
    user.username,
    product.id AS product_id,
    product.title
FROM report
LEFT JOIN user ON report.target_id = user.id  -- 유저 ID와 연결
LEFT JOIN product ON report.target_id = product.id  -- 상품 ID와 연결
JOIN user AS reporter ON report.reporter_id = reporter.id
""")    

    all_reports = cursor.fetchall()
    return render_template('admin_page.html', all_users=all_users, all_reports=all_reports)

# 관리자 페이지 -> 신고 대상 삭제
@app.route('/delete_reported_target/<target_id>', methods=['POST'])
def delete_reported_target(target_id):
    db = get_db()
    cursor = db.cursor()

    # 신고 대상이 상품인 경우 (상품 아이디가 존재하는지 확인)
    cursor.execute("SELECT * FROM product WHERE id = ?", (target_id,))
    product = cursor.fetchone()

    if product:
        # 상품이 존재하면 삭제
        cursor.execute("DELETE FROM product WHERE id = ?", (target_id,))
        cursor.execute("DELETE FROM report WHERE target_id = ?", (target_id,))  # 신고된 상품 삭제
        db.commit()
        flash('상품과 관련된 신고가 모두 삭제되었습니다.')
    else:
        # 신고 대상이 유저인 경우 (유저명이 존재하는지 확인)
        cursor.execute("SELECT * FROM user WHERE username = ?", (target_id,))
        user = cursor.fetchone()

        if user:
            # 유저가 존재하면 삭제
            cursor.execute("DELETE FROM user WHERE username = ?", (target_id,))
            cursor.execute("DELETE FROM report WHERE target_id = ?", (target_id,))  # 신고된 유저 삭제
            db.commit()
            flash(f"{target_id} 사용자가 강제 탈퇴 처리되었습니다.")
        else:
            flash("신고된 대상이 상품도 아니고 유저도 아닙니다.")

    return redirect(url_for('admin_page'))

#송금 기능
@app.route('/product/<product_id>/pay', methods=['GET', 'POST'])
def pay_product(product_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM product WHERE id = ?", (product_id,))
    product = cursor.fetchone()

    if not product:
        flash('상품을 찾을 수 없습니다.')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        payment_method = request.form['payment_method']
        flash(f"{payment_method.upper()} 방식으로 결제가 완료되었습니다.")
        return redirect(url_for('view_product', product_id=product_id))
    return render_template('payment.html', product=product)


if __name__ == '__main__':
    init_db()  # 앱 컨텍스트 내에서 테이블 생성
    socketio.run(app, debug=True)
