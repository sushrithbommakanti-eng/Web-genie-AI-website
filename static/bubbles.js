// 3D Bubble Effect
document.addEventListener('DOMContentLoaded', function() {
    const canvas = document.getElementById('bubble-canvas');
    const ctx = canvas.getContext('2d');
    
    // Set canvas size to window size
    function resizeCanvas() {
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;
    }
    
    // Call resize initially and on window resize
    resizeCanvas();
    window.addEventListener('resize', resizeCanvas);
    
    // Define gradient colors
    const gradientColors = [
        { r: 26, g: 42, b: 108 },  // #1a2a6c
        { r: 178, g: 31, b: 31 },  // #b21f1f
        { r: 253, g: 187, b: 45 }  // #fdbb2d
    ];
    
    // Bubble class
    class Bubble {
        constructor() {
            this.x = Math.random() * canvas.width;
            this.y = Math.random() * canvas.height;
            this.radius = Math.random() * 30 + 10;
            this.speedX = Math.random() * 0.5 - 0.25;
            this.speedY = Math.random() * 0.5 - 0.25;
            this.opacity = Math.random() * 0.5 + 0.1;
            
            // Randomly select a color from the gradient
            const colorIndex = Math.floor(Math.random() * gradientColors.length);
            const color = gradientColors[colorIndex];
            
            this.color = `rgba(${color.r}, ${color.g}, ${color.b}, ${this.opacity})`;
        }
        
        update() {
            this.x += this.speedX;
            this.y += this.speedY;
            
            // Bounce off edges
            if (this.x < this.radius || this.x > canvas.width - this.radius) {
                this.speedX = -this.speedX;
            }
            if (this.y < this.radius || this.y > canvas.height - this.radius) {
                this.speedY = -this.speedY;
            }
        }
        
        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = this.color;
            ctx.fill();
            
            // Add 3D effect with gradient
            const gradient = ctx.createRadialGradient(
                this.x - this.radius * 0.3, 
                this.y - this.radius * 0.3, 
                this.radius * 0.1,
                this.x, 
                this.y, 
                this.radius
            );
            gradient.addColorStop(0, 'rgba(255, 255, 255, 0.8)');
            gradient.addColorStop(1, 'rgba(255, 255, 255, 0)');
            ctx.fillStyle = gradient;
            ctx.fill();
        }
    }
    
    // Create bubbles
    const bubbles = [];
    const bubbleCount = Math.floor((canvas.width * canvas.height) / 15000) + 10;
    
    for (let i = 0; i < bubbleCount; i++) {
        bubbles.push(new Bubble());
    }
    
    // Animation loop
    function animate() {
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        // Update and draw bubbles
        bubbles.forEach(bubble => {
            bubble.update();
            bubble.draw();
        });
        
        // Draw connections between nearby bubbles
        drawConnections();
        
        requestAnimationFrame(animate);
    }
    
    // Draw connections between nearby bubbles
    function drawConnections() {
        for (let i = 0; i < bubbles.length; i++) {
            for (let j = i + 1; j < bubbles.length; j++) {
                const dx = bubbles[i].x - bubbles[j].x;
                const dy = bubbles[i].y - bubbles[j].y;
                const distance = Math.sqrt(dx * dx + dy * dy);
                
                if (distance < 150) {
                    const opacity = (1 - distance / 150) * 0.2;
                    ctx.beginPath();
                    ctx.moveTo(bubbles[i].x, bubbles[i].y);
                    ctx.lineTo(bubbles[j].x, bubbles[j].y);
                    ctx.strokeStyle = `rgba(253, 187, 45, ${opacity})`;
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }
            }
        }
    }
    
    // Start animation
    animate();
    
    // Add mouse interaction
    let mouseX = 0;
    let mouseY = 0;
    
    canvas.addEventListener('mousemove', (e) => {
        mouseX = e.clientX;
        mouseY = e.clientY;
        
        // Push bubbles away from mouse
        bubbles.forEach(bubble => {
            const dx = mouseX - bubble.x;
            const dy = mouseY - bubble.y;
            const distance = Math.sqrt(dx * dx + dy * dy);
            
            if (distance < 100) {
                const angle = Math.atan2(dy, dx);
                const force = (100 - distance) / 10;
                bubble.x -= Math.cos(angle) * force;
                bubble.y -= Math.sin(angle) * force;
            }
        });
    });
}); 