const { createClient } = require('@supabase/supabase-js');

exports.handler = async function(event, context) {
    // Only allow POST requests
    if (event.httpMethod !== 'POST') {
        return {
            statusCode: 405,
            body: JSON.stringify({ error: 'Method not allowed' })
        };
    }

    try {
        const data = JSON.parse(event.body);
        const { email, password, name } = data;

        // Validate input
        if (!email || !password || !name) {
            return {
                statusCode: 400,
                body: JSON.stringify({ error: 'Missing required fields' })
            };
        }

        // Initialize Supabase
        const supabaseUrl = process.env.SUPABASE_URL;
        const supabaseKey = process.env.SUPABASE_SERVICE_KEY;
        
        if (!supabaseUrl || !supabaseKey) {
            return {
                statusCode: 500,
                body: JSON.stringify({ error: 'Server configuration error' })
            };
        }

        const supabase = createClient(supabaseUrl, supabaseKey);

        // Create user with Supabase Auth
        const { data: authData, error: authError } = await supabase.auth.admin.createUser({
            email,
            password,
            email_confirm: true,
            user_metadata: { name }
        });

        if (authError) {
            console.error('Auth error:', authError);
            return {
                statusCode: 400,
                body: JSON.stringify({ error: authError.message })
            };
        }

        // Create user profile
        const { error: profileError } = await supabase
            .from('users')
            .insert([
                {
                    id: authData.user.id,
                    email: authData.user.email,
                    name: name,
                    created_at: new Date().toISOString(),
                    meditation_streak: 0,
                    total_meditations: 0,
                    journal_entries: 0,
                    role: 'user'
                }
            ]);

        if (profileError) {
            console.error('Profile error:', profileError);
            
            // Cleanup: Delete the auth user if profile creation fails
            await supabase.auth.admin.deleteUser(authData.user.id);
            
            return {
                statusCode: 500,
                body: JSON.stringify({ error: 'Failed to create user profile' })
            };
        }

        return {
            statusCode: 200,
            body: JSON.stringify({ 
                success: true, 
                message: 'User created successfully',
                user: {
                    id: authData.user.id,
                    email: authData.user.email,
                    name: name
                }
            })
        };

    } catch (error) {
        console.error('Signup error:', error);
        return {
            statusCode: 500,
            body: JSON.stringify({ error: 'Internal server error' })
        };
    }
};