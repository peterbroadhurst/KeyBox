/**
 * Copyright 2013 Sean Kavanagh - sean.p.kavanagh6@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.keybox.manage.db;

import java.io.IOException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import com.keybox.manage.model.Auth;
import com.keybox.manage.util.DBUtils;
import com.keybox.manage.util.EncryptionUtil;

/**
 * DAO to login administrative users
 */
public class AuthDB {

	/**
	 * auth user and return auth token if valid auth
	 * 
	 * @param auth
	 *            username and password object
	 * @return auth token if success
	 */
	public static String login(final Auth auth) {
		String authToken = null;

		// First do a JAAS login to validate the password
		boolean jaasSuccessful = false;
		try {
			CallbackHandler handler = new CallbackHandler() {
				@Override
				public void handle(Callback[] callbacks) throws IOException,
						UnsupportedCallbackException {
					for (Callback callback : callbacks) {
						if (callback instanceof NameCallback) {
							((NameCallback) callback).setName(auth
									.getUsername());
						} else if (callback instanceof PasswordCallback) {
							((PasswordCallback) callback).setPassword(auth
									.getPassword().toCharArray());
						}
					}
				}
			};

			try {
				LoginContext loginContext = new LoginContext("KeyboxLogin",
						handler);
				// starts the actual login
				loginContext.login();
				jaasSuccessful = true;
			} catch (LoginException e) {
				// log error (failed to authenticate the user - do something
				// about it)
				e.printStackTrace();				
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		Connection con = null;
		if (jaasSuccessful) try {
			con = DBUtils.getConn();
			int retryCount = 0;
			boolean obtainedDBDetails = false;
			while (!obtainedDBDetails && retryCount++ <= 1) {
				// login
				PreparedStatement stmt = con
						.prepareStatement("select * from users where enabled=true and username=?");
				stmt.setString(1, auth.getUsername());
				ResultSet rs = stmt.executeQuery();
				if (rs.next()) {
					auth.setId(rs.getLong("id"));
					obtainedDBDetails = true;
				}
				else {
					// This user doesn't exist in our auth DB yet. Create it
					PreparedStatement pStmt = con.prepareStatement("insert into users (username, user_type) values(?,?)");
					pStmt.setString(1, auth.getUsername());
					pStmt.setString(2, Auth.MANAGER);
					pStmt.execute();
					DBUtils.closeStmt(pStmt);			
				}				
				DBUtils.closeRs(rs);
				DBUtils.closeStmt(stmt);
			}
			authToken = UUID.randomUUID().toString();
			auth.setAuthToken(authToken);
			// set auth token
			updateLogin(con, auth);
					
		} catch (Exception e) {
			e.printStackTrace();
		}
		DBUtils.closeConn(con);
		return authToken;

	}

	/**
	 * checks to see if user is an admin based on auth token
	 * 
	 * @param authToken
	 *            auth token string
	 * @return user type if authorized, null if not authorized
	 */
	public static String isAuthorized(String authToken) {

		String authorized = null;

		Connection con = null;
		if (authToken != null && !authToken.trim().equals("")) {

			try {
				con = DBUtils.getConn();
				PreparedStatement stmt = con
						.prepareStatement("select * from users where enabled=true and auth_token=?");
				stmt.setString(1, authToken);
				ResultSet rs = stmt.executeQuery();

				if (rs.next()) {
					authorized = rs.getString("user_type");
				}
				DBUtils.closeRs(rs);

				DBUtils.closeStmt(stmt);

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		DBUtils.closeConn(con);
		return authorized;

	}

	/**
	 * updates the admin table based on auth id
	 * 
	 * @param con
	 *            DB connection
	 * @param auth
	 *            username and password object
	 */
	private static void updateLogin(Connection con, Auth auth) {

		try {
			PreparedStatement stmt = con
					.prepareStatement("update users set username=?, auth_token=? where id=?");
			stmt.setString(1, auth.getUsername());
			stmt.setString(2, auth.getAuthToken());
			stmt.setLong(3, auth.getId());
			stmt.execute();

			DBUtils.closeStmt(stmt);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * returns user id based on auth token
	 * 
	 * @param authToken
	 *            auth token
	 * @param con
	 *            DB connection
	 * @return user id
	 */
	public static Long getUserIdByAuthToken(Connection con, String authToken) {

		Long userId = null;
		try {
			PreparedStatement stmt = con
					.prepareStatement("select * from users where enabled=true and auth_token like ?");
			stmt.setString(1, authToken);
			ResultSet rs = stmt.executeQuery();
			if (rs.next()) {
				userId = rs.getLong("id");
			}
			DBUtils.closeRs(rs);
			DBUtils.closeStmt(stmt);

		} catch (Exception e) {
			e.printStackTrace();
		}

		return userId;

	}

	/**
	 * returns user id based on auth token
	 * 
	 * @param authToken
	 *            auth token
	 * @return user id
	 */
	public static Long getUserIdByAuthToken(String authToken) {

		Long userId = null;
		Connection con = null;
		try {
			con = DBUtils.getConn();
			userId = getUserIdByAuthToken(con, authToken);
		} catch (Exception e) {
			e.printStackTrace();
		}
		DBUtils.closeConn(con);

		return userId;

	}

	/**
	 * returns the shared secret based on user id
	 * 
	 * @param userId
	 *            user id
	 * @return auth object
	 */
	public static String getSharedSecret(Long userId) {

		String sharedSecret = null;
		Connection con = null;
		try {
			con = DBUtils.getConn();
			PreparedStatement stmt = con
					.prepareStatement("select * from users where id like ?");
			stmt.setLong(1, userId);
			ResultSet rs = stmt.executeQuery();
			if (rs.next()) {
				sharedSecret = EncryptionUtil.decrypt(rs
						.getString("otp_secret"));
			}
			DBUtils.closeRs(rs);
			DBUtils.closeStmt(stmt);

		} catch (Exception e) {
			e.printStackTrace();
		}
		DBUtils.closeConn(con);

		return sharedSecret;

	}

	/**
	 * updates shared secret based on auth token
	 * 
	 * @param secret
	 *            OTP shared secret
	 * @param authToken
	 *            auth token
	 */
	public static void updateSharedSecret(String secret, String authToken) {

		Connection con = null;
		try {
			con = DBUtils.getConn();
			PreparedStatement stmt = con
					.prepareStatement("update users set otp_secret=? where auth_token=?");
			stmt.setString(1, EncryptionUtil.encrypt(secret));
			stmt.setString(2, authToken);
			stmt.execute();
			DBUtils.closeStmt(stmt);

		} catch (Exception e) {
			e.printStackTrace();
		}
		DBUtils.closeConn(con);

	}

}
