// script.js
import { initializeApp } from "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
import { 
  getAuth, 
  createUserWithEmailAndPassword, 
  signInWithEmailAndPassword,
  onAuthStateChanged,
  signOut
} from "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";

console.log("SCRIPT LOADED");

// Firebase config
const firebaseConfig = {
  apiKey: "AIzaSyDEeZ8t4-UhSQR59FincDITv4ehgNNmsNY",
  authDomain: "scan-33bc9.firebaseapp.com",
  projectId: "scan-33bc9",
  storageBucket: "scan-33bc9.firebasestorage.app",
  messagingSenderId: "423271551477",
  appId: "1:423271551477:web:9632a5bdf64a18ff4fd0bc"
};

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);

// ================= AUTH FUNCTIONS =================

function signup() {
  console.log("Signup clicked");

  const email = document.getElementById("email")?.value.trim();
  const password = document.getElementById("password")?.value.trim();

  if (!email || !password) {
    alert("Please enter email and password");
    return;
  }

  createUserWithEmailAndPassword(auth, email, password)
    .then(() => {
      alert("Account created!");
      window.location.href = "index.html";
    })
    .catch(err => alert(err.message));
}

function login() {
  console.log("Login clicked");

  const email = document.getElementById("email")?.value.trim();
  const password = document.getElementById("password")?.value.trim();

  if (!email || !password) {
    alert("Please enter email and password");
    return;
  }

  signInWithEmailAndPassword(auth, email, password)
    .then(() => {
      alert("Logged in!");
      window.location.href = "index.html";
    })
    .catch(err => alert(err.message));
}

// ================= AUTH PAGE =================

const loginBtn = document.getElementById("loginBtn");
const signupBtn = document.getElementById("signupBtn");
const formTitle = document.getElementById("formTitle");
const switchText = document.getElementById("switchText");

if (loginBtn && signupBtn) {
  signupBtn.addEventListener("click", () => {
    if (formTitle) formTitle.textContent = "Sign Up";
    if (switchText) switchText.textContent = "Create a new account";
    signup();
  });

  loginBtn.addEventListener("click", () => {
    if (formTitle) formTitle.textContent = "Login";
    if (switchText) switchText.textContent = "Welcome back!";
    login();
  });
}

// ================= HOME PAGE =================

const authBtn = document.getElementById("authBtn");
const welcomeText = document.getElementById("welcomeText");

if (authBtn && welcomeText) {
  onAuthStateChanged(auth, (user) => {
    if (user) {
      authBtn.textContent = "Logout";
      authBtn.href = "#";

      welcomeText.textContent = "Hello, User 👋";

      authBtn.onclick = () => {
        signOut(auth).then(() => {
          alert("Logged out");
          window.location.reload();
        });
      };
    } else {
      authBtn.textContent = "Login";
      authBtn.href = "auth.html";
      welcomeText.textContent = "";
    }
  });
}