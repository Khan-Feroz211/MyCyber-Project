#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# IMPROVEMENT 3: Toast Notifications System
# Time: 1 hour
# Priority: MEDIUM (Better UX)
# ═══════════════════════════════════════════════════════════════

echo "🔔 IMPROVEMENT 3: Adding Toast Notifications"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

cd ../..
mkdir -p static/js

cat > static/js/toast.js << 'TOAST'
// Toast Notification System
class Toast {
    constructor() {
        this.container = this.createContainer();
        document.body.appendChild(this.container);
        this.addStyles();
    }

    createContainer() {
        const container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 10000;
            display: flex;
            flex-direction: column;
            gap: 10px;
        `;
        return container;
    }

    addStyles() {
        const style = document.createElement('style');
        style.textContent = `
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(400px);
                    opacity: 0;
                }
            }
        `;
        document.head.appendChild(style);
    }

    show(message, type = 'info', duration = 3000) {
        const toast = document.createElement('div');
        const colors = {
            success: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
            error: 'linear-gradient(135deg, #ef4444 0%, #dc2626 100%)',
            warning: 'linear-gradient(135deg, #f59e0b 0%, #d97706 100%)',
            info: 'linear-gradient(135deg, #4facfe 0%, #00f2fe 100%)'
        };
        const icons = {
            success: '✓',
            error: '✕',
            warning: '⚠',
            info: 'ℹ'
        };

        toast.style.cssText = `
            background: ${colors[type]};
            color: white;
            padding: 15px 20px;
            border-radius: 12px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.3);
            min-width: 300px;
            max-width: 400px;
            animation: slideIn 0.3s ease-out;
            display: flex;
            align-items: center;
            gap: 10px;
        `;

        toast.innerHTML = `
            <span style="font-size: 1.2rem; font-weight: bold;">${icons[type]}</span>
            <span style="flex: 1;">${message}</span>
            <button onclick="this.parentElement.remove()" 
                    style="background:none;border:none;color:white;cursor:pointer;font-size:1.2rem;padding:0;">×</button>
        `;

        this.container.appendChild(toast);

        setTimeout(() => {
            toast.style.animation = 'slideOut 0.3s ease-out';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    success(msg, dur) { this.show(msg, 'success', dur); }
    error(msg, dur) { this.show(msg, 'error', dur); }
    warning(msg, dur) { this.show(msg, 'warning', dur); }
    info(msg, dur) { this.show(msg, 'info', dur); }
}

// Global instance
window.toast = new Toast();

// Auto-convert Flask flash messages to toasts
document.addEventListener('DOMContentLoaded', function() {
    const flashMessages = document.querySelectorAll('.alert');
    flashMessages.forEach(function(alert) {
        const type = alert.classList.contains('alert-success') ? 'success' :
                    alert.classList.contains('alert-danger') ? 'error' :
                    alert.classList.contains('alert-warning') ? 'warning' : 'info';
        const message = alert.textContent.trim();
        window.toast.show(message, type);
        alert.remove(); // Remove original flash message
    });
});
TOAST

echo "✅ Toast system created: static/js/toast.js"
echo ""
echo "📝 To use:"
echo "   Add to base.html before </body>:"
echo "   <script src=\"{{ url_for('static', filename='js/toast.js') }}\"></script>"
echo ""
echo "   JavaScript usage:"
echo "   toast.success('Operation successful!');"
echo "   toast.error('Something went wrong!');"
echo "   toast.warning('Please check your input');"
echo "   toast.info('Processing...');"
echo ""
