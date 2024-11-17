import cabbage from "../assets/images/cabbage.jpg"
import potatoes from "../assets/images/potatoes.jpg"
import tommatoes from "../assets/images/tommatoes.jpg"
import Yam from "../assets/images/Yam.jpg"
import Avocado from "../assets/images/Avocado.png"
import Cucumber2 from "../assets/images/Cucumber2.jpg"
import Ginger from "../assets/images/Ginger.jpg"
import Garlic from "../assets/images/Garlic.jpg"
import plantain1 from "../assets/images/plantain1.webp"
import Onion from "../assets/images/Onion.jpg"
import Carrot from "../assets/images/Carrot.jpg"
import ripeplantain from "../assets/images/ripeplantain.jpg"
import okro from "../assets/images/okro.jpg"
import PepperImage from "../assets/images/pepper.jpg"
import Pepper1 from "../assets/images/Pepper1.webp"
import greengrapes from "../assets/images/greengrapes.webp"
import greenpepper from "../assets/images/greenpepper.webp"
import greenp3 from "../assets/images/greenp3.jpg"
import cassava1 from "../assets/images/cassava1.jpg"
import tangerine from "../assets/images/tangerine.jpg"
import palmnut from "../assets/images/palmnut.jpeg"
import maize from "../assets/images/maize.jpeg"
import redpepper from "../assets/images/redpepper.jpg"
import mango from "../assets/images/mango.jpg"
import Lettuce from "../assets/images/Lettuce.webp"
import springonion from "../assets/images/springonion.webp"



const products = [

   
    {
        image: potatoes,
        name: "Fresh Potatoes",
        price: 100,
        quantity: "8 pieces per bag",
        description: "Our Fresh Potatoes are grown in local farms, contains alot of nutrients and are tasty.",
        category:  "Vegetables"
    },
   
   
    {
        image: greengrapes,
        name: "Grapes",
        price: 75,
        quantity: "2kg pieces per bag",
        description: "Our Grapes are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
    {
        image: Cucumber2,
        name: "Cucumber",
        price: 50,
        quantity: "4 pieces per bag",
        description: "Our Local Cucumber are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Vegetables"
    },
   

    {
        image: Yam,
        name: "Yam",
        price: 35,
        quantity: "Each Yam is 35 cedis",
        description: "Our Fresh Potatoes are grown in local farms, contains alot of nutrients and are tasty.",
        category:  "Vegetables"
    },

    {
        image: plantain1,
        name: "Apem Plantain",
        price: 150,
        quantity: "15 pieces per bag",
        description: "Our Plantains are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },


    {
        image: Garlic,
        name: "Garlic",
        price: 70,
        quantity: "3kg per bag",
        description: "Nutritious garlic for all your cooking.",
        category:  "Vegetables"
    },
    

    {
        image: Ginger,
        name: "Local Ginger",
        price: 30,
        quantity: "10 pieces per bag",
        description: "Our Gingers are grown in local farms",
        category:  "Vegetables"
    },

 {
        image: tommatoes,
        name: "Fresh Tomatoes",
        price: 200,
        quantity: "10kg",
        description: "Our Fresh Tomatoes is filled with so much nutrients as they are grown in local farms and taste sweet.",
        category:  "Vegetables"
    },


    {
        image: cabbage,
        name: "Local Cabbage",
        price: 50,
        quantity: "4 peices per bag",
        description: "Our local cabbages are grown in local farms and are fresh and hydrated",
        category:  "Vegetables"
    },

    {
        image: Onion,
        name: "Onions",
        price: 100,
        quantity: "20 pieces per pack",
        description: "Our Onions are grown in local farms and are fresh and hydrated",
        category:  "Fruites"
    },
    {
        image: Carrot,
        name: "Local Carrots",
        price: 80,
        quantity: "15 pieces per bag",
        description: "Our Local Carrots are grown in local farms, contains alot of nutrients,fresh and tastes great.",
        category:  "Vegetables"
    },
    {
        image: ripeplantain,
        name: "Ripe Plantain",
        price: 60,
        quantity: "3 pieces per bag",
        description: "Our Ripe Plantain are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
  
    {
        image: PepperImage,
        name: "Bell-Pepper",
        price: 70,
        quantity: "6 pieces per bag",
        description: "The pack contains 2 peices of each color",
        category:  "Vegetables"
    },
    {
        image: Avocado,
        name: "Avocado",
        price: 60,
        quantity: "3 pieces per bag",
        description: "Our Avocados are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
    {
        image: greenp3,
        name: "Green Pepper",
        price: 30,
        quantity: "5 pieces per bag",
        description: "Our Green Pepper are grown in local farms and are fresh and hydrated",
        category:  "Vegetables"
    },
    {
        image: cassava1,
        name: "Cassava",
        price: 50,
        quantity: "10 pieces per bag",
        description: "Our Cassava are grown in local farms and are fresh and hydrated",
        category:  "Fruites"
    },
    {
        image: palmnut,
        name: "Palm Nut",
        price: 50,
        quantity: "5kg  per bag",
        description: "Our Palm Nuts are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
    {
        image: maize,
        name: "Maize",
        price: 40,
        quantity: "10 pieces per bag",
        description: "Our Maizes are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
   
    {
        image: redpepper,
        name: "Red Bell-Pepper",
        price: 80,
        quantity: "5 pieces per bag",
        description: "Our Red Bell Pepper are grown in local farms and are fresh and hydrated",
        category:  "Fruites"
    },
    {
        image: Pepper1,
        name: "Local Red Pepper",
        price: 50,
        quantity: "2kg  per bag",
        description: "Our Local Pepper are grown in local farms and are fresh and hydrated",
        category:  "Fruites"
    },
    {
        image: greenpepper,
        name: "Local Green Pepper",
        price: 50,
        quantity: "2kg  per bag",
        description:"Our Local Pepper are grown in local farms and are fresh and hydrated",
        category:  "Fruites"
    },
    {
        image: Lettuce,
        name: "Local Lettuce",
        price: 60,
        quantity: "3kg per bag",
        description: "Our Local Lettuce are grown in local farms and are fresh and hydrated",
        category:  "Vegetables"
    },
    {
        image: greengrapes,
        name: "Grapes",
        price: 75,
        quantity: "2kg pieces per bag",
        description: "Our Grapes are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
    {
        image: tangerine,
        name: "Tangarine",
        price: 50,
        quantity: "2kg per bag",
        description: "Our Local Tangarine are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
    {
        image: springonion,
        name: "Spring Onions",
        price: 35,
        quantity: "2kg  per bag",
        description: "Our Spring Onions are grown in local farms and are fresh and hydrated",
        category:  "Vegetables"
    },

    {
        image: Yam,
        name: "Yam",
        price: 35,
        quantity: "Each Yam is 35 cedis",
        description: "Our Fresh Potatoes are grown in local farms, contains alot of nutrients and are tasty.",
        category:  "Vegetables"
    },

    {
        image: mango,
        name: "Local Mango",
        price: 60,
        quantity: "3kg per pack",
        description: "Our Local Mangoes are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
    {
        image: Avocado,
        name: "Avocado",
        price: 60,
        quantity: "3 pieces per bag",
        description: "Our Avocados are grown in local farms, contains alot of nutrients and tastes great.",
        category:  "Fruites"
    },
    {
        image: cabbage,
        name: "Local Cabbage",
        price: 50,
        quantity: "4 peices per bag",
        description: "Our local cabbages are grown in local farms and are fresh and hydrated",
        category:  "Vegetables"
    },

    {
        image: okro,
        name: "Okra",
        price: 60,
        quantity: "10kg per pack",
        description: "Our Okro are grown in local farms and are fresh and hydrated",
        category:  "Fruites"
    },
 
    

]


export default products