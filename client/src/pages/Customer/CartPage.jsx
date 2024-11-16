
import React,{useState} from 'react';
import "../../styles/Customer/Cartpage.css";
import spinachImage from '../../assets/cart-images/spinach pic.jpeg'
import tomatoImage from '../../assets/cart-images/tomato pic.jpg'
const CartPage = () => {
  const [cart,setCart] = useState([
    {id:1, name:'spinach',price: 20, qauntity:1,  image: spinachImage
  },
    {id:2, name :'tomatoes',price:30, qauntity:1,   image: tomatoImage
  }
  ]);
  const updateQauntity = (id,qauntity)=>{
    setCart((prevCart)=>
      prevCart.map((item)=>
        item.id === id?{...item,qauntity:qauntity} : item
  )
)
  }
  //to delete item from cart
  const deleteItem = (id)=>{
    setCart((prevCart)=> prevCart.filter((item)=> item.id !==id));
  
  
  }
    // total price calculation
    const totalPrice =() => 
      cart.reduce((total,item)=> total + item.price*item.qauntity,0);
  return (
    <div className = "Cart-main-container">
      
      
      <div className='Cart-container'>
      <h1  className='Cart-heading'>CART</h1>
      {cart.length === 0 ? (<p className='Cart-Para1'>Your Cart is Empty</p>):(
        <>
      <ul>
        {cart.map((item)=>(
          <li key = {item.id}>
            <img
                    src={item.image}
                    alt={item.name}
                    style={{ width: '80px', marginRight: '10px', height:'50px' }}
                  />
            <h3 className='Cart-item'>{item.name}</h3>
            <p>Price: ${item.price}</p>
            <p>Quantity:</p>
            <input
            type= "number"
            min= "1"
            value= {item.qauntinty}
            onChange={(e)=> updateQauntity(item.id,parseInt(e.target.value))}
            />
            <br></br>
            <button className='Cart-deleteBtn' onClick={()=> deleteItem(item.id)}>Remove Item </button>
          </li>
        )
        )}
      </ul>
      <h3>Total: ${totalPrice()}</h3>
      <button className='Cart-checkoutBtn' onClick={()=> alert('Proceeding to checkout')}>Checkout</button>
      </>
      
      )
      
    }
      </div>
      


      </div>
  )
}

export default CartPage;