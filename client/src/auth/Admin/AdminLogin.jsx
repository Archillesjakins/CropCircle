import React from "react";
import AdminBg from "../../assets/Background-images/side-view-women-shaking-hands.jpeg";

const AdminLogin = () => {
  const formData = {
    email: "",
    password: "",
  };
  const dummyData = {
    email: "admin@admin.com",
    password: "789",
  };

  const [error, setError] = React.useState("");
  const [form, setForm] = React.useState(formData);
  const [emailError, setEmailError] = React.useState("");
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

  function HandleChange(e) {
    setForm({ ...form, [e.target.name]: e.target.value });
    if (!emailRegex.test(e.target.value)) {
      setEmailError("Please Enter a valid email address");
    }

    console.log(form);
  }

  function HandleSubmit(e) {
    e.preventDefault();
    if (form.email === "" || form.password === "") {
      alert("Please fill the form");
      return;
    }
    if (
      form.email === dummyData.email &&
      form.password === dummyData.password
    ) {
      window.location.href = "/admin/*";
    } else {
      alert("Wrong Credentials");
      setForm(formData);
    }
    // try{
    //    const response = fetch("http://localhost:8000/api/admin/login", form)
    //    if(response.status === 200){
    //      alert("Login Successful")
    //      window.location.href = "/admin/dashboard"
    //      return;
    //    }
    //    else{
    //      alert("Invalid Credentials")
    //      return;
    //    }
    // }
    // catch(error){
    //   setError(error);
    // }
    setForm(formData);
    console.log("Results", form);
  }
  return (
    <div
      className="flex items-center justify-center min-h-screen bg-cover"
      style={{ backgroundImage: `url(${AdminBg})` }}
    >
      <div className="p-14 w-11/12 md:w-full max-w-lg bg-gray-300 opacity-90 rounded-3xl shadow-lg">
        <h1 className="font-bold text-3xl text-center text-green-600 mb-4">
          CROPCIRCLE
        </h1>
        <h2 className="text-xl font-semibold text-center">
          Welcome Back, Admin
        </h2>
        <p className="text-center mb-6">Sign In to continue</p>

        <form onSubmit={HandleSubmit} action="" className="space-y-4">
          <input
            type="email"
            placeholder="Email"
            name="email"
            onChange={HandleChange}
            value={form.email}
            className="w-full p-3 rounded-md border border-gray-400 focus:outline-none focus:border-green-500"
          />
          <input
            type="password"
            placeholder="Password"
            name="password"
            onChange={HandleChange}
            value={form.password}
            className="w-full p-3 rounded-md border border-gray-400 focus:outline-none focus:border-green-500"
          />
          <button
            type="submit"
            className="w-full py-3 font-semibold text-white transition bg-green-600 rounded-xl hover:bg-green-700"
          >
            Sign In
          </button>
          <p className="mt-4 text-sm text-center">
            <a href="" className="text-gray-600 hover:underline">
              Forgot Password?
            </a>
          </p>
        </form>
      </div>
    </div>
  );
};

export default AdminLogin;
