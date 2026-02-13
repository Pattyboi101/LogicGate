/**
 * Whitchurch MOT & Service Centre - Backend Server
 *
 * A lightweight Express server to handle booking submissions
 * and serve static files for the website.
 *
 * Run with: node server.js
 * Server will start on http://localhost:3000
 */

const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Data file path for storing bookings
const DATA_FILE = path.join(__dirname, 'bookings.json');

// Middleware
app.use(express.json());
app.use(express.static(__dirname));

// Initialize bookings file if it doesn't exist
function initDataFile() {
    if (!fs.existsSync(DATA_FILE)) {
        fs.writeFileSync(DATA_FILE, JSON.stringify([], null, 2));
        console.log('Created bookings.json data file');
    }
}

// Read bookings from file
function readBookings() {
    try {
        const data = fs.readFileSync(DATA_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading bookings:', error);
        return [];
    }
}

// Write bookings to file
function writeBookings(bookings) {
    try {
        fs.writeFileSync(DATA_FILE, JSON.stringify(bookings, null, 2));
        return true;
    } catch (error) {
        console.error('Error writing bookings:', error);
        return false;
    }
}

// API Routes

// GET /api/bookings - Get all bookings
app.get('/api/bookings', (req, res) => {
    const bookings = readBookings();
    res.json(bookings);
});

// POST /api/bookings - Create a new booking
app.post('/api/bookings', (req, res) => {
    const { name, phone, email, vehicleReg, serviceType, preferredDate, message } = req.body;

    // Validation
    if (!name || !phone || !vehicleReg || !serviceType || !preferredDate) {
        return res.status(400).json({
            error: 'Missing required fields',
            required: ['name', 'phone', 'vehicleReg', 'serviceType', 'preferredDate']
        });
    }

    // Create booking object
    const booking = {
        id: Date.now().toString(),
        name: name.trim(),
        phone: phone.trim(),
        email: email ? email.trim() : '',
        vehicleReg: vehicleReg.trim().toUpperCase(),
        serviceType,
        preferredDate,
        message: message ? message.trim() : '',
        status: 'pending',
        submittedAt: new Date().toISOString()
    };

    // Save booking
    const bookings = readBookings();
    bookings.push(booking);

    if (writeBookings(bookings)) {
        console.log(`New booking received: ${booking.name} - ${booking.serviceType} - ${booking.preferredDate}`);
        res.status(201).json({
            message: 'Booking submitted successfully',
            booking
        });
    } else {
        res.status(500).json({ error: 'Failed to save booking' });
    }
});

// GET /api/bookings/:id - Get a specific booking
app.get('/api/bookings/:id', (req, res) => {
    const bookings = readBookings();
    const booking = bookings.find(b => b.id === req.params.id);

    if (!booking) {
        return res.status(404).json({ error: 'Booking not found' });
    }

    res.json(booking);
});

// PATCH /api/bookings/:id - Update a booking (e.g., change status)
app.patch('/api/bookings/:id', (req, res) => {
    const bookings = readBookings();
    const index = bookings.findIndex(b => b.id === req.params.id);

    if (index === -1) {
        return res.status(404).json({ error: 'Booking not found' });
    }

    // Update allowed fields
    const allowedUpdates = ['status', 'preferredDate', 'message'];
    const updates = {};

    for (const field of allowedUpdates) {
        if (req.body[field] !== undefined) {
            updates[field] = req.body[field];
        }
    }

    // Validate status if provided
    if (updates.status && !['pending', 'confirmed', 'completed', 'cancelled'].includes(updates.status)) {
        return res.status(400).json({
            error: 'Invalid status',
            validStatuses: ['pending', 'confirmed', 'completed', 'cancelled']
        });
    }

    // Apply updates
    bookings[index] = { ...bookings[index], ...updates, updatedAt: new Date().toISOString() };

    if (writeBookings(bookings)) {
        console.log(`Booking ${req.params.id} updated`);
        res.json(bookings[index]);
    } else {
        res.status(500).json({ error: 'Failed to update booking' });
    }
});

// DELETE /api/bookings/:id - Delete a booking
app.delete('/api/bookings/:id', (req, res) => {
    const bookings = readBookings();
    const index = bookings.findIndex(b => b.id === req.params.id);

    if (index === -1) {
        return res.status(404).json({ error: 'Booking not found' });
    }

    const deleted = bookings.splice(index, 1)[0];

    if (writeBookings(bookings)) {
        console.log(`Booking ${req.params.id} deleted`);
        res.json({ message: 'Booking deleted', booking: deleted });
    } else {
        res.status(500).json({ error: 'Failed to delete booking' });
    }
});

// Serve index.html for the root route
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'index.html'));
});

// Serve admin.html for /admin route
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// 404 handler
app.use((req, res) => {
    res.status(404).sendFile(path.join(__dirname, 'index.html'));
});

// Error handler
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ error: 'Internal server error' });
});

// Initialize and start server
initDataFile();

app.listen(PORT, () => {
    console.log(`
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Whitchurch MOT & Service Centre - Server Running        ║
║                                                           ║
║   Website:  http://localhost:${PORT}                        ║
║   Admin:    http://localhost:${PORT}/admin                  ║
║                                                           ║
║   Admin Password: whitchurch2024                          ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
    `);
});

module.exports = app;
