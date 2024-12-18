import unittest 
from flask import  current_app
from app import create_app, db            


class BasicTestCase(unittest.TestCase):
    def setUp(self):
        self.app = create_app('testing')
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        
    def tearDown(self):
        db.session_remove()
        db.drop_all()
        self.app_context.pop()
        
    def test_app_exsists(self):
        self.assertFalse(current_app is None)
        
    def test_app_is_testing(self):
        self.assertTrue(current_app.config['TESTING'])
        
        
    @ app.cli.command()
    def test():
        """Run the unit tests"""
        import unitests
        tests = unittest.TestLoader().discover('tests')
        unittest.TextTestRunner(verbosity=2).run(tests)
        