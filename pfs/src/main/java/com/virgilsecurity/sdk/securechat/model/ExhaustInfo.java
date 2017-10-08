package com.virgilsecurity.sdk.securechat.model;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import com.google.gson.annotations.SerializedName;

/**
 * @author Andrii Iakovenko
 *
 */
public class ExhaustInfo {

	public static class ExhaustInfoEntry {
		@SerializedName("identifier")
		private String identifier;

		@SerializedName("exhaust_date")
		private Date exhaustDate;

		/**
		 * Create new instance of {@link ExhaustInfoEntry}.
		 */
		public ExhaustInfoEntry() {
			super();
		}

		/**
		 * Create new instance of {@link ExhaustInfoEntry}.
		 * 
		 * @param identifier
		 *            the identifier.
		 * @param exhaustDate
		 *            the exhaust date.
		 */
		public ExhaustInfoEntry(String identifier, Date exhaustDate) {
			super();
			this.identifier = identifier;
			this.exhaustDate = exhaustDate;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#equals(java.lang.Object)
		 */
		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			ExhaustInfoEntry other = (ExhaustInfoEntry) obj;
			if (exhaustDate == null) {
				if (other.exhaustDate != null)
					return false;
			} else if (!exhaustDate.equals(other.exhaustDate))
				return false;
			if (identifier == null) {
				if (other.identifier != null)
					return false;
			} else if (!identifier.equals(other.identifier))
				return false;
			return true;
		}

		/**
		 * @return the exhaustDate
		 */
		public Date getExhaustDate() {
			return exhaustDate;
		}

		/**
		 * @return the identifier
		 */
		public String getIdentifier() {
			return identifier;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#hashCode()
		 */
		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((exhaustDate == null) ? 0 : exhaustDate.hashCode());
			result = prime * result + ((identifier == null) ? 0 : identifier.hashCode());
			return result;
		}

		/**
		 * @param exhaustDate
		 *            the exhaustDate to set
		 */
		public void setExhaustDate(Date exhaustDate) {
			this.exhaustDate = exhaustDate;
		}

		/**
		 * @param identifier
		 *            the identifier to set
		 */
		public void setIdentifier(String identifier) {
			this.identifier = identifier;
		}
	}

	public static class SessionExhaustInfo {
		@SerializedName("identifier")
		private byte[] identifier;

		@SerializedName("card_id")
		private String cardId;

		@SerializedName("exhaust_date")
		private Date exhaustDate;

		/**
		 * Create new instance of {@link SessionExhaustInfo}.
		 */
		public SessionExhaustInfo() {
			super();
		}

		/**
		 * Create new instance of {@link SessionExhaustInfo}.
		 * 
		 * @param identifier
		 *            the session identifier.
		 * @param cardId
		 *            the card identifier.
		 * @param exhaustDate
		 *            the exhaust date.
		 */
		public SessionExhaustInfo(byte[] identifier, String cardId, Date exhaustDate) {
			super();
			this.identifier = identifier;
			this.cardId = cardId;
			this.exhaustDate = exhaustDate;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#equals(java.lang.Object)
		 */
		@Override
		public boolean equals(Object obj) {
			if (this == obj)
				return true;
			if (obj == null)
				return false;
			if (getClass() != obj.getClass())
				return false;
			SessionExhaustInfo other = (SessionExhaustInfo) obj;
			if (cardId == null) {
				if (other.cardId != null)
					return false;
			} else if (!cardId.equals(other.cardId))
				return false;
			if (exhaustDate == null) {
				if (other.exhaustDate != null)
					return false;
			} else if (!exhaustDate.equals(other.exhaustDate))
				return false;
			if (!Arrays.equals(identifier, other.identifier))
				return false;
			return true;
		}

		/**
		 * @return the cardId
		 */
		public String getCardId() {
			return cardId;
		}

		/**
		 * @return the exhaustDate
		 */
		public Date getExhaustDate() {
			return exhaustDate;
		}

		/**
		 * @return the identifier
		 */
		public byte[] getIdentifier() {
			return identifier;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see java.lang.Object#hashCode()
		 */
		@Override
		public int hashCode() {
			final int prime = 31;
			int result = 1;
			result = prime * result + ((cardId == null) ? 0 : cardId.hashCode());
			result = prime * result + ((exhaustDate == null) ? 0 : exhaustDate.hashCode());
			result = prime * result + Arrays.hashCode(identifier);
			return result;
		}

		/**
		 * @param cardId
		 *            the cardId to set
		 */
		public void setCardId(String cardId) {
			this.cardId = cardId;
		}

		/**
		 * @param exhaustDate
		 *            the exhaustDate to set
		 */
		public void setExhaustDate(Date exhaustDate) {
			this.exhaustDate = exhaustDate;
		}

		/**
		 * @param identifier
		 *            the identifier to set
		 */
		public void setIdentifier(byte[] identifier) {
			this.identifier = identifier;
		}

	}

	@SerializedName("otc")
	private List<ExhaustInfoEntry> otc;

	@SerializedName("ltc")
	private List<ExhaustInfoEntry> ltc;

	@SerializedName("sessions")
	private List<SessionExhaustInfo> sessions;

	/**
	 * 
	 */
	public ExhaustInfo() {
		otc = new ArrayList<>();
		ltc = new ArrayList<>();
		sessions = new ArrayList<>();
	}

	/**
	 * @param otc
	 * @param ltc
	 * @param sessions
	 */
	public ExhaustInfo(List<ExhaustInfoEntry> otc, List<ExhaustInfoEntry> ltc, List<SessionExhaustInfo> sessions) {
		this();
		if (otc != null) {
			this.otc = otc;
		}
		if (ltc != null) {
			this.ltc = ltc;
		}
		if (sessions != null) {
			this.sessions = sessions;
		}
	}

	/**
	 * @return the ltc
	 */
	public List<ExhaustInfoEntry> getLtc() {
		return ltc;
	}

	/**
	 * @return the otc
	 */
	public List<ExhaustInfoEntry> getOtc() {
		return otc;
	}

	/**
	 * @return the sessions
	 */
	public List<SessionExhaustInfo> getSessions() {
		return sessions;
	}

	/**
	 * @param ltc
	 *            the ltc to set
	 */
	public void setLtc(List<ExhaustInfoEntry> ltc) {
		this.ltc = ltc;
	}

	/**
	 * @param otc
	 *            the otc to set
	 */
	public void setOtc(List<ExhaustInfoEntry> otc) {
		this.otc = otc;
	}

	/**
	 * @param sessions
	 *            the sessions to set
	 */
	public void setSessions(List<SessionExhaustInfo> sessions) {
		this.sessions = sessions;
	}

}
