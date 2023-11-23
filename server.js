const express=require('express')
const app=express()
const admin=require("firebase-admin")
const credentials=require("./serviceAccKey.json")
const PORT=3000

app.use(express.json())
app.use(express.urlencoded({extended:true}))

admin.initializeApp({
    credential:admin.credential.cert(credentials)
})

const isAuthenticated = async (req, res, next) => {
    const idToken = req.headers.authorization;
  
    try {
      // Verify the Firebase ID token
      const decodedToken = await admin.auth().verifyIdToken(idToken);
      req.user = decodedToken; // Attach the user information to the request object
      next(); // Move on to the next middleware or route handler
    } catch (error) {
      console.error('Error verifying Firebase ID token:', error);
      res.status(401).json({ error: 'Unauthorized' });
    }
  };


app.post('/signup',async (req,res)=>{
    const userRes=await admin.auth().createUser({
        email:req.body.email,
        password:req.body.password,
        emailVerified:false,
        disabled:false
    })
    res.json(userRes)
})


app.post('/signin', async (req, res) => {
    const { email, password } = req.body;
  
    try {
      // Authenticate the user using the provided email and password
      const userCredential = await admin.auth().getUserByEmail(email);
      // In this case, you're not comparing passwords directly with the Admin SDK.
      // Instead, you can assume success if no exception is thrown.
  
      // Create a custom token for the authenticated user
      const customToken = await admin.auth().createCustomToken(userCredential.uid);
  
      res.json({ token: customToken });
    } catch (error) {
      console.error('Error signing in user:', error);
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });

app.get('/secure-data', isAuthenticated, (req, res) => {
    // Access the authenticated user information using req.user
    const userEmail = req.user.email;
    res.json({ message: `This is secure data for user ${userEmail}` });
  });



app.listen(PORT,()=>{
    console.log('server running on port : ',PORT)
})