import { StatusCodes } from 'http-status-codes'
import { pickUser } from '~/utils/formatters'
import { authenticator } from 'otplib'
import QRCode from 'qrcode'
import _, { last } from 'lodash'

// LƯU Ý: Trong ví dụ về xác thực 2 lớp Two-Factor Authentication (2FA) này thì chúng ta sẽ sử dụng nedb-promises để lưu và truy cập dữ liệu từ một file JSON. Coi như file JSON này là Database của dự án.
const Datastore = require('nedb-promises')
const UserDB = Datastore.create('src/database/users.json')
const TwoFactorSecretKeyDB = Datastore.create('src/database/2fa_secret_keys.json')
const UserSessionDB = Datastore.create('src/database/user_sessions.json')
const SERVICE_NAME = '2FA-duckhanhdev'

const login = async (req, res) => {
  try {
    const user = await UserDB.findOne({ email: req.body.email })
    // Không tồn tại user
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }
    // Kiểm tra mật khẩu "đơn giản". LƯU Ý: Thực tế phải dùng bcryptjs để hash mật khẩu, đảm bảo mật khẩu được bảo mật. Ở đây chúng ta làm nhanh gọn theo kiểu so sánh string để tập trung vào nội dung chính là 2FA.
    // Muốn học về bcryptjs cũng như toàn diện kiến thức đầy đủ về việc làm một trang web Nâng Cao thì các bạn có thể theo dõi khóa MERN Stack Advanced này. (Public lên phần hội viên của kênh vào tháng 12/2024)
    // https://www.youtube.com/playlist?list=PLP6tw4Zpj-RJbPQfTZ0eCAXH_mHQiuf2G
    if (user.password !== req.body.password) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Wrong password!' })
      return
    }

    let resUser = pickUser(user)
    let currentUserSession = await UserSessionDB.findOne({
      user_id: user._id,
      device_id: req.headers['user-agent']
    })
    if (!currentUserSession) {
      currentUserSession = await UserSessionDB.insert({
        user_id: user._id,
        device_id: req.headers['user-agent'],
        is_2fa_verified: false, // Mới đăng nhập lần đầu nên chưa xác thực 2FA
        last_login_at: new Date().valueOf()
      })
    }
    resUser['is_2fa_verified'] = currentUserSession.is_2fa_verified
    resUser['last_login_at'] = currentUserSession.last_login_at

    res.status(StatusCodes.OK).json(resUser)
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const getUser = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    let resUser = pickUser(user)
    // Nếu user đã bật 2FA thì chúng ta sẽ tìm kiếm sesion hiện tại của user theo userId và deviceId(userAgent)
    // if (user.require_2fa) {
    const currentUserSession = await UserSessionDB.findOne({
      user_id: user._id,
      device_id: req.headers['user-agent']
    })

    resUser['is_2fa_verified'] = currentUserSession ? currentUserSession.is_2fa_verified : null
    resUser['last_login_at'] = currentUserSession ? currentUserSession.last_login_at : null
    // }

    res.status(StatusCodes.OK).json(resUser)
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const logout = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }

    // Khi user đăng xuất thì chúng ta sẽ xoá phiên cảu user theo user_id và device_id trong DB > user_sessions.json
    // await UserSessionDB.deleteOne({
    await UserSessionDB.deleteMany({
      user_id: user._id,
      device_id: req.headers['user-agent']
    })
    UserSessionDB.compactDatafileAsync()

    res.status(StatusCodes.OK).json({ loggedOut: true })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const get2FA_QRCode = async (req, res) => {
  try {
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }
    // Biến lưu trữ 2fa secret key của user
    let twoFactorSecretKeyValue = null
    // Lấy secret key của user từ bảng 2fa_secret_keys
    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({ user_id: user._id })
    if (!twoFactorSecretKey) {
      // Nếu chưa có secret key riêng của user thì tạo mới secret key cho user
      const newTwoFactorSecretKey = await TwoFactorSecretKeyDB.insert({
        user_id: user._id,
        value: authenticator.generateSecret() // generateSecret() là một hàm otplib để tạo ra 
        //random secret key mới đúng chuẩn
      })
      twoFactorSecretKeyValue = newTwoFactorSecretKey.value
    } else {
      // Ngược lại nếu user có rồi thì ta sử dụng luôn
      twoFactorSecretKeyValue = twoFactorSecretKey.value
    }
    // Tạo OTP Auth token 
    const otpAuthToken = authenticator.keyuri(
      user.username,
      SERVICE_NAME,
      twoFactorSecretKeyValue
    )

    // Tạo một ảnh QR Code từ token OTP để gửi về cho client
    const QRCodeImageUrl = await QRCode.toDataURL(otpAuthToken)

    res.status(StatusCodes.OK).json({ qrcode: QRCodeImageUrl })
  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

const setup2FA = async (req, res) => {
  try {
    // B1: Lấy thông tin user từ bảng users
    const user = await UserDB.findOne({ _id: req.params.id })
    if (!user) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'User not found!' })
      return
    }
    // B2: Lấy secret key của user từ bảng 2fa_secret_keys
    const twoFactorSecretKey = await TwoFactorSecretKeyDB.findOne({ user_id: user._id })
    if (!twoFactorSecretKey) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'Two-factor Secret Key not found' })
      return
    }

    // B3: Nếu user đã có secret key thì ta sẽ kiểm tra OTP token từ client gửi lên
    const clientOTPToken = req.body.otpToken
    if (!clientOTPToken) {
      res.status(StatusCodes.NOT_FOUND).json({ message: 'OTP Token not found' })
      return
    }
    const isValid = authenticator.verify({
      token: clientOTPToken,
      secret: twoFactorSecretKey.value
    })
    if (!isValid) {
      res.status(StatusCodes.NOT_ACCEPTABLE).json({ message: 'Isvalid OTP Token' })
      return
    }

    // B4: Nếu OTP token hợp lệ thì ta sẽ cập nhật thông tin user là đã bật 2FA
    const updatedUser = await UserDB.update(
      { _id: user._id },
      { $set: { require_2fa: true } },
      { returnUpdatedDocs: true }
    )
    /** Sau mỗi hành động update(cập nhật bản ghi), cần phải chạy compact này vì đây là cơ chế của NeDB
     * mà chúng ta đang sử dụng, nó sẽ loại bỏ bản ghi cũ và giữ lại bản ghi mới cập nhật. Nếu bạn không thực
     * hiện bước compact này thì dẫn đến dữ liệu trong file users.json sẽ bị lỗi, không thể đọc được.
     * Nói chugn nếu dùng database chuẩn như MongoDB hay Mysql thì không cần care tới cái này, chẳng qua chúng
     * ta muốn làm nhanh database bằng JSON nên mới cần follow tới NeDB.
     * https://github.com/seald/nedb/blob/HEAD/API.md#nedbcompactdatafileasync   */
    UserDB.compactDatafileAsync()

    /** B5: Lúc này tuỳ vào spec  dự án mà sẽ giữ phiên đăng nhập hợp lệ của user hoặc yêu cầu user bắt buộc
     *  phải đăng nhập lại. Cái này tuỳ theo nhu cầu.
     *  Ở đây sẽ chọn giữ lại phiên đăng nhập hợp lệ của user. Khi nào user chủ động đăng xuất và đăng nhập lại
     *  trên một device khác thì mới yêu cầu require_2fa
     *  Vì user lúc này mới bật 2fa nên chúng ta sẽ tạo một phiên đăng nhập hợp lệ cho user với định danh
     *  trình duyệt hiện tại   */
    const newUserSession = await UserSessionDB.insert({
      user_id: user._id,
      // Lấy userAgent từ request headers để định danh trình duyệt của user (device_id)
      device_id: req.headers['user-agent'],
      // Xác định phiên đăng này là hợp lệ với 2fa
      is_2fa_verified: true,
      last_login_at: new Date().valueOf()
    })

    // B6: Trả về dữ liệu cần thiết cho phía FE
    res.status(StatusCodes.OK).json({
      ...pickUser(updatedUser),
      is_2fa_verified: newUserSession.is_2fa_verified,
      last_login_at: newUserSession.last_login_at
    })

  } catch (error) {
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json(error)
  }
}

export const userController = {
  login,
  getUser,
  logout,
  get2FA_QRCode,
  setup2FA
}
