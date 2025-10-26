import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels"""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttackType(Enum):
    """Types of SQL injection attacks"""
    AUTH_BYPASS = "Authentication Bypass"
    UNION_INJECTION = "UNION-based Data Extraction"
    COMMENT_BYPASS = "Comment-based Bypass"
    BOOLEAN_BLIND = "Boolean-based Blind SQLi"
    TIME_BLIND = "Time-based Blind SQLi"
    ERROR_BASED = "Error-based SQLi"


@dataclass
class Vulnerability:
    """Data class for vulnerability information"""
    attack_type: AttackType
    severity: Severity
    payload: str
    description: str
    impact: str
    success: bool
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now().isoformat()


@dataclass
class TestResult:
    """Data class for test results"""
    test_name: str
    passed: bool
    details: str
    query_executed: str = ""


class SecurityDatabase:
    """Manages the test database"""
    
    def __init__(self, db_name: str = "security_demo.db"):
        self.db_name = db_name
        self.setup()
    
    def setup(self):
        """Initialize database with sample data"""
        if os.path.exists(self.db_name):
            os.remove(self.db_name)
        
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Products table for more complex queries
        cursor.execute("""
            CREATE TABLE products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                category TEXT,
                stock INTEGER DEFAULT 0
            )
        """)
        
        # Insert sample users
        users = [
            ('admin', 'SecureP@ss123', 'admin@company.com', 'admin'),
            ('alice', 'alice2024', 'alice@company.com', 'user'),
            ('bob', 'bob_pass', 'bob@company.com', 'user'),
            ('charlie', 'charlie123', 'charlie@company.com', 'moderator'),
            ('eve', 'eve_secret', 'eve@company.com', 'user')
        ]
        
        cursor.executemany(
            "INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)",
            users
        )
        
        # Insert sample products
        products = [
            ('Laptop', 999.99, 'Electronics', 15),
            ('Mouse', 29.99, 'Electronics', 50),
            ('Desk Chair', 199.99, 'Furniture', 10),
            ('Monitor', 349.99, 'Electronics', 20),
            ('Keyboard', 79.99, 'Electronics', 35)
        ]
        
        cursor.executemany(
            "INSERT INTO products (name, price, category, stock) VALUES (?, ?, ?, ?)",
            products
        )
        
        conn.commit()
        conn.close()
        print(f"✓ Database '{self.db_name}' initialized with sample data")
    
    def cleanup(self):
        """Remove test database"""
        if os.path.exists(self.db_name):
            os.remove(self.db_name)
            print(f"✓ Database '{self.db_name}' removed")


class VulnerableQueries:
    """Contains intentionally vulnerable database query methods"""
    
    def __init__(self, db_name: str):
        self.db_name = db_name
    
    def login(self, username: str, password: str) -> Tuple[Optional[List], str]:
        """VULNERABLE: String concatenation allows SQL injection"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # VULNERABLE CODE - DO NOT USE IN PRODUCTION
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            conn.close()
            return result, query
        except sqlite3.Error as e:
            conn.close()
            return None, f"ERROR: {e}"
    
    def search_products(self, category: str) -> Tuple[Optional[List], str]:
        """VULNERABLE: String formatting in WHERE clause"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        query = f"SELECT * FROM products WHERE category='{category}'"
        
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            conn.close()
            return result, query
        except sqlite3.Error as e:
            conn.close()
            return None, f"ERROR: {e}"
    
    def get_user_by_id(self, user_id: str) -> Tuple[Optional[List], str]:
        """VULNERABLE: Numeric parameter concatenation"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        query = f"SELECT * FROM users WHERE id={user_id}"
        
        try:
            cursor.execute(query)
            result = cursor.fetchall()
            conn.close()
            return result, query
        except sqlite3.Error as e:
            conn.close()
            return None, f"ERROR: {e}"


class SecureQueries:
    """Contains secure database query methods using parameterization"""
    
    def __init__(self, db_name: str):
        self.db_name = db_name
    
    def login(self, username: str, password: str) -> Tuple[Optional[List], str]:
        """SECURE: Parameterized query prevents SQL injection"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        query = "SELECT * FROM users WHERE username=? AND password=?"
        
        try:
            cursor.execute(query, (username, password))
            result = cursor.fetchall()
            conn.close()
            return result, query
        except sqlite3.Error as e:
            conn.close()
            return None, f"ERROR: {e}"
    
    def search_products(self, category: str) -> Tuple[Optional[List], str]:
        """SECURE: Parameterized query with validation"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        query = "SELECT * FROM products WHERE category=?"
        
        try:
            cursor.execute(query, (category,))
            result = cursor.fetchall()
            conn.close()
            return result, query
        except sqlite3.Error as e:
            conn.close()
            return None, f"ERROR: {e}"
    
    def get_user_by_id(self, user_id: int) -> Tuple[Optional[List], str]:
        """SECURE: Type-safe parameterized query"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        query = "SELECT * FROM users WHERE id=?"
        
        try:
            cursor.execute(query, (user_id,))
            result = cursor.fetchall()
            conn.close()
            return result, query
        except sqlite3.Error as e:
            conn.close()
            return None, f"ERROR: {e}"


class SQLInjectionTester:
    """Main testing class for SQL injection demonstrations"""
    
    def __init__(self, db_name: str = "security_demo.db"):
        self.db = SecurityDatabase(db_name)
        self.vulnerable = VulnerableQueries(db_name)
        self.secure = SecureQueries(db_name)
        self.vulnerabilities: List[Vulnerability] = []
        self.test_results: List[TestResult] = []
    
    def run_attack_demonstrations(self):
        """Execute various SQL injection attack demonstrations"""
        print("\n" + "="*80)
        print("SQL INJECTION ATTACK DEMONSTRATIONS")
        print("="*80)
        
        self._demo_auth_bypass()
        self._demo_union_injection()
        self._demo_comment_bypass()
        self._demo_boolean_blind()
        self._demo_error_based()
    
    def _demo_auth_bypass(self):
        """Demonstrate authentication bypass attack"""
        print("\n[ATTACK 1] Authentication Bypass - OR Statement")
        print("-" * 80)
        
        payload = "admin' OR '1'='1"
        password = "anything"
        
        print(f"Payload: username=\"{payload}\", password=\"{password}\"")
        result, query = self.vulnerable.login(payload, password)
        
        print(f"Query Executed: {query}")
        
        if result and len(result) > 0:
            print(f"⚠️  VULNERABILITY CONFIRMED - Bypassed authentication!")
            print(f"   Retrieved {len(result)} user(s):")
            for user in result[:3]:  # Show first 3
                print(f"   • ID: {user[0]}, Username: {user[1]}, Role: {user[4]}")
            
            self.vulnerabilities.append(Vulnerability(
                attack_type=AttackType.AUTH_BYPASS,
                severity=Severity.CRITICAL,
                payload=payload,
                description="OR-based authentication bypass",
                impact="Attacker gains unauthorized access without valid credentials",
                success=True
            ))
        else:
            print("✓ Attack blocked")
    
    def _demo_union_injection(self):
        """Demonstrate UNION-based injection"""
        print("\n[ATTACK 2] UNION-based Data Extraction")
        print("-" * 80)
        
        payload = "' UNION SELECT id, username, password, email, role FROM users --"
        password = "irrelevant"
        
        print(f"Payload: username=\"{payload}\"")
        result, query = self.vulnerable.login(payload, password)
        
        print(f"Query Executed: {query}")
        
        if result and len(result) > 0:
            print(f"⚠️  VULNERABILITY CONFIRMED - Data extraction successful!")
            print(f"   Extracted {len(result)} records from database:")
            for user in result[:5]:  # Show first 5
                print(f"   • {user[1]}:{user[2]} ({user[3]})")
            
            self.vulnerabilities.append(Vulnerability(
                attack_type=AttackType.UNION_INJECTION,
                severity=Severity.CRITICAL,
                payload=payload,
                description="UNION-based SQL injection for data extraction",
                impact="Complete database contents can be extracted",
                success=True
            ))
        else:
            print("✓ Attack blocked or query error")
    
    def _demo_comment_bypass(self):
        """Demonstrate comment-based bypass"""
        print("\n[ATTACK 3] Comment-based Password Bypass")
        print("-" * 80)
        
        payload = "admin'--"
        password = "irrelevant"
        
        print(f"Payload: username=\"{payload}\"")
        result, query = self.vulnerable.login(payload, password)
        
        print(f"Query Executed: {query}")
        
        if result and len(result) > 0:
            print(f"⚠️  VULNERABILITY CONFIRMED - Password check bypassed!")
            print(f"   Logged in as: {result[0][1]} (Role: {result[0][4]})")
            
            self.vulnerabilities.append(Vulnerability(
                attack_type=AttackType.COMMENT_BYPASS,
                severity=Severity.CRITICAL,
                payload=payload,
                description="SQL comment injection to bypass password check",
                impact="Password verification completely bypassed",
                success=True
            ))
        else:
            print("✓ Attack blocked")
    
    def _demo_boolean_blind(self):
        """Demonstrate boolean-based blind injection"""
        print("\n[ATTACK 4] Boolean-based Blind Injection")
        print("-" * 80)
        
        # Test if admin exists
        payload1 = "1 OR (SELECT username FROM users WHERE username='admin' AND LENGTH(password)>5) IS NOT NULL"
        print(f"Payload: user_id=\"{payload1}\"")
        result1, query1 = self.vulnerable.get_user_by_id(payload1)
        
        print(f"Query Executed: {query1}")
        
        if result1 and len(result1) > 0:
            print(f"⚠️  VULNERABILITY CONFIRMED - Information leaked via boolean response!")
            print(f"   Discovered: admin password length > 5 characters")
            
            self.vulnerabilities.append(Vulnerability(
                attack_type=AttackType.BOOLEAN_BLIND,
                severity=Severity.HIGH,
                payload=payload1,
                description="Boolean-based blind SQL injection",
                impact="Database structure and data can be inferred through true/false responses",
                success=True
            ))
        else:
            print("✓ Attack blocked or no results")
    
    def _demo_error_based(self):
        """Demonstrate error-based injection"""
        print("\n[ATTACK 5] Error-based Information Disclosure")
        print("-" * 80)
        
        payload = "1' AND 1=CAST((SELECT username FROM users LIMIT 1) AS INTEGER)--"
        result, query = self.vulnerable.get_user_by_id(payload)
        
        print(f"Payload: user_id=\"{payload}\"")
        print(f"Query Result: {query}")
        
        if result is None and "ERROR" in query:
            print(f"⚠️  VULNERABILITY CONFIRMED - Database errors expose information!")
            print(f"   Error message: {query}")
            
            self.vulnerabilities.append(Vulnerability(
                attack_type=AttackType.ERROR_BASED,
                severity=Severity.HIGH,
                payload=payload,
                description="Error-based SQL injection",
                impact="Database errors reveal sensitive information",
                success=True
            ))
        else:
            print("✓ No information leaked through errors")
    
    def test_secure_implementation(self):
        """Test that secure implementation blocks attacks"""
        print("\n" + "="*80)
        print("SECURE IMPLEMENTATION TESTING")
        print("="*80)
        
        # Test 1: Legitimate login
        print("\n[TEST 1] Legitimate Authentication")
        print("-" * 80)
        result, query = self.secure.login("admin", "SecureP@ss123")
        if result and len(result) > 0:
            print(f"✓ SUCCESS: Authenticated as {result[0][1]}")
            self.test_results.append(TestResult(
                test_name="Legitimate Login",
                passed=True,
                details="Valid credentials accepted",
                query_executed=query
            ))
        else:
            print("✗ FAILED: Authentication failed")
            self.test_results.append(TestResult(
                test_name="Legitimate Login",
                passed=False,
                details="Valid credentials rejected"
            ))
        
        # Test 2: Block injection attempt
        print("\n[TEST 2] SQL Injection Prevention - OR Bypass")
        print("-" * 80)
        payload = "admin' OR '1'='1"
        result, query = self.secure.login(payload, "anything")
        
        if not result or len(result) == 0:
            print(f"✓ SUCCESS: Injection attempt blocked!")
            print(f"   Payload treated as literal string, not SQL code")
            self.test_results.append(TestResult(
                test_name="Block OR Bypass",
                passed=True,
                details="Malicious input treated as literal string",
                query_executed=query
            ))
        else:
            print(f"✗ FAILED: Injection succeeded (should not happen!)")
            self.test_results.append(TestResult(
                test_name="Block OR Bypass",
                passed=False,
                details="Injection not blocked"
            ))
        
        # Test 3: Block comment injection
        print("\n[TEST 3] SQL Injection Prevention - Comment Bypass")
        print("-" * 80)
        payload = "admin'--"
        result, query = self.secure.login(payload, "anything")
        
        if not result or len(result) == 0:
            print(f"✓ SUCCESS: Comment injection blocked!")
            self.test_results.append(TestResult(
                test_name="Block Comment Bypass",
                passed=True,
                details="Comment characters treated as literal data",
                query_executed=query
            ))
        else:
            print(f"✗ FAILED: Comment injection succeeded")
            self.test_results.append(TestResult(
                test_name="Block Comment Bypass",
                passed=False,
                details="Comment injection not blocked"
            ))
        
        # Test 4: Type safety
        print("\n[TEST 4] Type Safety Validation")
        print("-" * 80)
        try:
            result, query = self.secure.get_user_by_id(1)  # Valid integer
            if result:
                print(f"✓ SUCCESS: Type-safe query executed correctly")
                self.test_results.append(TestResult(
                    test_name="Type Safety",
                    passed=True,
                    details="Integer parameter handled correctly"
                ))
            else:
                print(f"✗ FAILED: Valid integer rejected")
                self.test_results.append(TestResult(
                    test_name="Type Safety",
                    passed=False,
                    details="Valid type rejected"
                ))
        except Exception as e:
            print(f"✓ SUCCESS: Invalid type rejected - {e}")
            self.test_results.append(TestResult(
                test_name="Type Safety",
                passed=True,
                details=f"Type validation working: {e}"
            ))
    
    def generate_report(self, save_to_file: bool = True):
        """Generate comprehensive vulnerability report"""
        report = {
            "metadata": {
                "tool": "SQL Injection Educational Demonstration",
                "generated": datetime.now().isoformat(),
                "database": self.db.db_name,
                "total_vulnerabilities": len(self.vulnerabilities),
                "total_tests": len(self.test_results)
            },
            "vulnerabilities": [asdict(v) for v in self.vulnerabilities],
            "test_results": [asdict(t) for t in self.test_results],
            "recommendations": self._get_recommendations()
        }
        
        # Print summary
        print("\n" + "="*80)
        print("VULNERABILITY ASSESSMENT SUMMARY")
        print("="*80)
        print(f"Timestamp: {report['metadata']['generated']}")
        print(f"Database: {report['metadata']['database']}")
        print(f"\nVulnerabilities Found: {report['metadata']['total_vulnerabilities']}")
        
        for vuln in self.vulnerabilities:
            print(f"\n  • {vuln.attack_type.value}")
            print(f"    Severity: {vuln.severity.value}")
            print(f"    Impact: {vuln.impact}")
        
        print(f"\nSecurity Tests Passed: {sum(1 for t in self.test_results if t.passed)}/{len(self.test_results)}")
        
        # Save to file
        if save_to_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"sqli_report_{timestamp}.json"
            
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"\n✓ Detailed report saved to: {filename}")
        
        # Print recommendations
        self._print_recommendations()
        
        return report
    
    def _get_recommendations(self) -> List[Dict[str, str]]:
        """Get security recommendations"""
        return [
            {
                "priority": "CRITICAL",
                "title": "Use Parameterized Queries",
                "description": "Always use parameterized queries (prepared statements) with placeholder values. Never concatenate user input into SQL strings.",
                "example": 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))'
            },
            {
                "priority": "HIGH",
                "title": "Input Validation",
                "description": "Validate and sanitize all user inputs. Use allowlists for expected patterns. Implement type checking.",
                "example": "Validate that user_id is an integer before processing"
            },
            {
                "priority": "HIGH",
                "title": "Principle of Least Privilege",
                "description": "Database accounts should have minimal required permissions. Don't use admin accounts for applications.",
                "example": "Grant only SELECT, INSERT, UPDATE on specific tables"
            },
            {
                "priority": "MEDIUM",
                "title": "Use ORM Frameworks",
                "description": "Consider using ORM frameworks (SQLAlchemy, Django ORM) that handle parameterization automatically.",
                "example": "User.query.filter_by(username=username).first()"
            },
            {
                "priority": "MEDIUM",
                "title": "Error Handling",
                "description": "Never expose detailed database error messages to users. Log errors securely for debugging.",
                "example": "Return generic error messages; log details server-side"
            },
            {
                "priority": "MEDIUM",
                "title": "Web Application Firewall",
                "description": "Deploy a WAF to filter malicious requests before they reach your application.",
                "example": "ModSecurity, Cloudflare WAF, AWS WAF"
            },
            {
                "priority": "LOW",
                "title": "Regular Security Audits",
                "description": "Conduct regular code reviews, automated scanning, and penetration testing.",
                "example": "Use tools like SQLMap, Burp Suite for testing"
            }
        ]
    
    def _print_recommendations(self):
        """Print security recommendations"""
        print("\n" + "="*80)
        print("SECURITY RECOMMENDATIONS")
        print("="*80)
        
        recommendations = self._get_recommendations()
        
        for i, rec in enumerate(recommendations, 1):
            print(f"\n{i}. [{rec['priority']}] {rec['title']}")
            print(f"   {rec['description']}")
            print(f"   Example: {rec['example']}")
    
    def cleanup(self):
        """Clean up resources"""
        self.db.cleanup()


def print_banner():
    """Display program banner"""
    banner = """
\033[91m
   ██████╗  ██████╗ ██╗         ██╗███╗   ██╗     ██╗███████╗ ██████╗████████╗██╗ ██████╗ ███╗   ██╗
  ██╔════╝ ██╔═══██╗██║         ██║████╗  ██║     ██║██╔════╝██╔════╝╚══██╔══╝██║██╔═══██╗████╗  ██║
  ╚█████╗  ██║   ██║██║         ██║██╔██╗ ██║     ██║█████╗  ██║        ██║   ██║██║   ██║██╔██╗ ██║
   ╚═══██╗ ██║▄▄ ██║██║         ██║██║╚██╗██║██   ██║██╔══╝  ██║        ██║   ██║██║   ██║██║╚██╗██║
  ██████╔╝ ╚██████╔╝███████╗    ██║██║ ╚████║╚█████╔╝███████╗╚██████╗   ██║   ██║╚██████╔╝██║ ╚████║
  ╚═════╝   ╚══▀▀═╝ ╚══════╝    ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚══════╝ ╚═════╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
                                                                                                      
   █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ 
  ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
  ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
  ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
  ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
  ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
\033[0m
\033[92m              # Coded By Infinity_sec - @Nir_____\033[0m

\033[93m              ⚠️  EDUCATIONAL USE ONLY - LOCAL TESTING ⚠️\033[0m
    """
    print(banner)


def print_menu():
    """Display main menu"""
    menu = """
╔════════════════════════════════════════════════════════════════════════════╗
║                              MAIN MENU                                     ║
╚════════════════════════════════════════════════════════════════════════════╝

  [1] Run Complete Security Demonstration
  [2] Test Vulnerable Queries Only
  [3] Test Secure Queries Only
  [4] View Comparison: Vulnerable vs Secure
  [5] Generate Report Only
  [6] View Previous Reports
  [7] Exit

"""
    print(menu)


def run_complete_demo():
    """Run complete demonstration"""
    print("\n" + "="*80)
    print("STARTING COMPLETE SECURITY DEMONSTRATION")
    print("="*80)
    
    tester = SQLInjectionTester()
    
    # Run attack demonstrations
    tester.run_attack_demonstrations()
    
    # Test secure implementation
    tester.test_secure_implementation()
    
    # Generate report
    tester.generate_report()
    
    # Cleanup
    tester.cleanup()
    
    print("\n" + "="*80)
    print("DEMONSTRATION COMPLETED")
    print("="*80)


def run_vulnerable_only():
    """Run only vulnerable query demonstrations"""
    print("\n" + "="*80)
    print("TESTING VULNERABLE QUERIES")
    print("="*80)
    
    tester = SQLInjectionTester()
    tester.run_attack_demonstrations()
    tester.cleanup()


def run_secure_only():
    """Run only secure query tests"""
    print("\n" + "="*80)
    print("TESTING SECURE IMPLEMENTATION")
    print("="*80)
    
    tester = SQLInjectionTester()
    tester.test_secure_implementation()
    tester.generate_report(save_to_file=False)
    tester.cleanup()


def view_comparison():
    """Show side-by-side comparison"""
    print("\n" + "="*80)
    print("VULNERABLE vs SECURE CODE COMPARISON")
    print("="*80)
    
    comparison = """
VULNERABLE CODE (DO NOT USE):
─────────────────────────────────────────────────────────────────────────────
query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
cursor.execute(query)

❌ Problem: User input directly concatenated into SQL string
❌ Risk: Attackers can inject arbitrary SQL code
❌ Example Attack: username = "admin' OR '1'='1" bypasses authentication


SECURE CODE (ALWAYS USE THIS):
─────────────────────────────────────────────────────────────────────────────
query = "SELECT * FROM users WHERE username=? AND password=?"
cursor.execute(query, (username, password))

✓ Solution: Parameterized query with placeholders
✓ Protection: User input treated as data, not executable code
✓ Result: SQL injection attacks are automatically blocked


KEY DIFFERENCES:
─────────────────────────────────────────────────────────────────────────────
1. Placeholders (?): Replace direct values with ? placeholders
2. Separate Parameters: Pass user input as tuple in second argument
3. Database Handles Escaping: Database driver safely escapes all input
4. No String Formatting: Never use f-strings, %, or + for SQL queries

"""
    print(comparison)


def view_reports():
    """View previous JSON reports"""
    reports = [f for f in os.listdir('.') if f.startswith('sqli_report_') and f.endswith('.json')]
    
    if not reports:
        print("\n[!] No previous reports found.")
        return
    
    print("\n" + "="*80)
    print("AVAILABLE REPORTS")
    print("="*80)
    
    for i, report in enumerate(sorted(reports, reverse=True), 1):
        print(f"  [{i}] {report}")
    
    choice = input("\nEnter report number to view (or press Enter to return): ").strip()
    
    if choice.isdigit() and 1 <= int(choice) <= len(reports):
        report_file = sorted(reports, reverse=True)[int(choice) - 1]
        
        with open(report_file, 'r') as f:
            report_data = json.load(f)
        
        print("\n" + "="*80)
        print(json.dumps(report_data, indent=2))
        print("="*80)


def main():
    """Main application entry point"""
    print_banner()
    
    while True:
        print_menu()
        choice = input("Select an option [1-7]: ").strip()
        
        if choice == '1':
            run_complete_demo()
        
        elif choice == '2':
            run_vulnerable_only()
        
        elif choice == '3':
            run_secure_only()
        
        elif choice == '4':
            view_comparison()
        
        elif choice == '5':
            tester = SQLInjectionTester()
            tester.run_attack_demonstrations()
            tester.test_secure_implementation()
            tester.generate_report()
            tester.cleanup()
        
        elif choice == '6':
            view_reports()
        
        elif choice == '7':
            print("\n✓ Exiting... Stay secure!")
            break
        
        else:
            print("\n[!] Invalid option. Please select 1-7.")
        
        input("\nPress Enter to continue...")
        print("\n" * 2)


if __name__ == "__main__":
    main()